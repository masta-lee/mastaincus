import { protectedAgentFixture } from './fixtures/guest-protection.js'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { X509Certificate } from 'node:crypto'
import { IncusClient } from '../src/lib/incus/incus-client.js'
import { deleteInstance, stopInstance } from '../src/lib/incus/incus-instances.js'
import { verifyInstanceDeleted } from '../src/lib/incus/verify-instance-deleted.js'
import { ensureDedicatedForward } from '../src/lib/incus/dedicated-network.js'
import { prisma, closePrismaDatabase } from '../src/db/prisma.js'
import { poolCleanupRecord, processPoolCleanup, readPoolCleanup } from '../src/services/host-pool-cleanup.js'
import { PORT_PROTOCOL_CAPABILITY } from '../src/services/host-port-protocol.js'
import { dedicatedHostReadyWhere, HOST_OCCUPIED_INSTANCE_WHERE } from '../src/lib/host-resource-usage.js'
import { requestInstanceDeletion, readDeletionIntent } from '../src/services/instance-deletion.js'
import { requestUserCleanup, processUserCleanup } from '../src/services/admin-user-cleanup.js'
import { executeExpiryEnforcement } from '../src/services/billing-scheduler.js'
import { performRenewal } from '../src/db/billing-operations.js'
import { claimLightTask, executeTask } from '../src/workers/instanceTaskWorker.js'
import { RENEWAL_RESUME_ENTRY } from '../src/services/renewal-resume.js'
assert.equal(process.env.GITHUB_ACTIONS, 'true')
assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted')
const serverCertificate = readFileSync('/var/lib/incus/server.crt', 'utf8')
const client = new IncusClient({ url: 'https://127.0.0.1:18443', certPath: process.env.INCUDAL_CLEANUP_CLIENT_CERT!, keyPath: process.env.INCUDAL_CLEANUP_CLIENT_KEY!,
  serverCertificate, serverFingerprint: new X509Certificate(serverCertificate).fingerprint256 })
try {
  await client.connect()
  const before = await client.request<{ status: string }>('GET', '/1.0/instances/cleanup-guest')
  assert.equal(before.status, 'Running')
  assert.equal((await client.request<unknown[]>('GET', '/1.0/instances/cleanup-guest/snapshots?recursion=1')).length, 1)
  await ensureDedicatedForward(client, 'cleanup-guest', '192.0.2.99', '10.199.0.99')
  assert.equal((await client.request<unknown[]>('GET', '/1.0/networks/incusbr0/forwards?recursion=1')).length, 1)
  if (process.env.POOL_CLEANUP_WORKER === '1' || process.env.INSTANCE_DELETION_WORKER === '1' || process.env.EXPIRY_DELETION_WORKER === '1' || process.env.ACCOUNT_DELETION_WORKER === '1' || process.env.EXPIRY_RENEWAL_WORKER === '1') {
    const database = new URL(process.env.DATABASE_URL!)
    assert.equal(database.hostname, '127.0.0.1'); assert.ok(database.pathname.endsWith('_pool_test'))
    const actor = await prisma.user.create({ data: { username: 'actual-incus-fixture', role: 'admin', passwordHash: 'unused-fixture' } })
    const host = await prisma.host.create({ data: { userId: actor.id, name: 'actual-incus-fixture', url: 'https://127.0.0.1:18443',
      certPath: process.env.INCUDAL_CLEANUP_CLIENT_CERT, keyPath: process.env.INCUDAL_CLEANUP_CLIENT_KEY,
      serverCertificate, serverFingerprint: new X509Certificate(serverCertificate).fingerprint256,
      status: 'online', poolFaulted: true, singleTenant: true, isInstalled: true, instanceType: 'container',
      natPublicIp: '192.0.2.99', natBindIp: '192.0.2.99', resourcePreset: process.arch === 'arm64' ? 'ARM1C' : 'E2', customerDiskGiB: 30,
      architecture: process.arch === 'arm64' ? 'aarch64' : 'x86_64', cpuAllowanceMax: process.arch === 'arm64' ? 100 : 200,
      memoryMax: process.arch === 'arm64' ? 4096 : 768, storageSize: 34,
      cpuUsed: 200, memoryUsed: 768, diskUsed: 30720, natPortStart: 20000, natPortEnd: 30000,
      portProtocol: 'tcp', portProtocolRevision: 1, portProtocolApplied: 'tcp', portProtocolAppliedRevision: 1,
      agent: { create: { ...protectedAgentFixture([PORT_PROTOCOL_CAPABILITY]) } },
      storagePools: { create: { name: 'cleanup-test', driver: 'lvm', purpose: 'instance_data', config: { 'volume.block.filesystem': 'btrfs' } } } } })
    try {
      if (process.env.EXPIRY_RENEWAL_WORKER === '1') {
        await prisma.host.update({where:{id:host.id},data:{poolFaulted:false}})
        const guest=await client.request<{created_at:string;config:Record<string,string>}>('GET','/1.0/instances/cleanup-guest')
        const customer=await prisma.user.create({data:{username:'native-expiry-renew-buyer',passwordHash:'fixture',balance:20}})
        const pkg=await prisma.package.create({data:{userId:actor.id,name:'native-expiry-renew',cpuMax:host.cpuAllowanceMax,memoryMax:host.memoryMax,diskMax:30720}})
        const plan=await prisma.packagePlan.create({data:{packageId:pkg.id,name:'native-expiry-renew',cpu:host.cpuAllowanceMax,memory:host.memoryMax,disk:30720,price:1000,portLimit:0,snapshotLimit:0,backupLimit:0,siteLimit:0,trafficLimit:0n}})
        const instance=await prisma.instance.create({data:{userId:customer.id,hostId:host.id,packageId:pkg.id,packagePlanId:plan.id,name:'cleanup-guest',incusId:'cleanup-guest',
          image:'cleanup-fixture',status:'running',cpu:host.cpuAllowanceMax,memory:host.memoryMax,disk:30720,storagePoolName:'cleanup-test',billingPrice:10,billingCycle:1,autoRenew:false,expiresAt:new Date(Date.now()-60000),
          snapshottedSpecs:{recoveryIdentity:{uuid:guest.config['volatile.uuid'],createdAt:guest.created_at,project:'default'}}}})
        await executeExpiryEnforcement()
        assert.equal((await client.request<{status:string}>('GET','/1.0/instances/cleanup-guest')).status,'Stopped')
        const suspended=await prisma.instance.findUniqueOrThrow({where:{id:instance.id}});assert.equal(suspended.status,'suspended')
        await performRenewal(customer.id,suspended,1,undefined,{sid:'native-manual-renew',iat:Math.floor(Date.now()/1000)+1})
        const task=await prisma.instanceTask.findFirstOrThrow({where:{instanceId:instance.id,operationEntry:RENEWAL_RESUME_ENTRY}})
        const claim=await claimLightTask(host.id,task.id);assert.ok(claim);await executeTask(task.id,claim)
        assert.equal((await prisma.instanceTask.findUniqueOrThrow({where:{id:task.id}})).status,'COMPLETED')
        assert.equal((await prisma.instance.findUniqueOrThrow({where:{id:instance.id}})).status,'running')
        const running=await client.request<{status:string;config:Record<string,string>}>('GET','/1.0/instances/cleanup-guest')
        assert.equal(running.status,'Running');assert.equal(running.config['volatile.uuid'],guest.config['volatile.uuid'])
        assert.equal(await prisma.instanceBillingRecord.count({where:{instanceId:instance.id,type:'renew'}}),1)
        assert.equal((await prisma.user.findUniqueOrThrow({where:{id:customer.id}})).balance.toNumber(),10)
        await requestInstanceDeletion(await prisma.instance.findUniqueOrThrow({where:{id:instance.id}}),{id:actor.id,sid:'native-admin-cleanup',iat:Math.floor(Date.now()/1000)+1},{mode:'admin'})
        for(let check=0;check<200&&(await prisma.host.findUniqueOrThrow({where:{id:host.id}})).poolFaulted;check++)await new Promise(resolve=>setTimeout(resolve,100))
        assert.equal((await prisma.host.findUniqueOrThrow({where:{id:host.id}})).poolFaulted,false)
        await prisma.instance.delete({where:{id:instance.id}});await prisma.package.delete({where:{id:pkg.id}});await prisma.user.delete({where:{id:customer.id}})
        console.log('PASS native expiry -> Incus Stopped -> manual renewal with auto-renew off -> original worker resumes same guest Running; one debit and intact UUID')
      } else if (process.env.ACCOUNT_DELETION_WORKER === '1') {
        await prisma.host.update({where:{id:host.id},data:{poolFaulted:false}})
        const customer=await prisma.user.create({data:{username:'actual-account-delete-fixture',passwordHash:'unused-fixture',balance:12.34,hostingBalance:4,affBalance:5}})
        const instance=await prisma.instance.create({data:{userId:customer.id,hostId:host.id,name:'cleanup-guest',incusId:'cleanup-guest',
          image:'cleanup-fixture',status:'running',cpu:host.cpuAllowanceMax,memory:host.memoryMax,disk:30720,storagePoolName:'cleanup-test'}})
        await prisma.balanceLog.create({data:{userId:customer.id,instanceId:instance.id,type:'consume',amount:-11,balanceBefore:23.34,balanceAfter:12.34}})
        await prisma.instanceBillingRecord.create({data:{userId:customer.id,instanceId:instance.id,type:'newPurchase',amount:11,months:1,periodStart:new Date(),periodEnd:new Date(Date.now()+86400000)}})
        const deletingActor={id:actor.id,sid:'disposable-account-cleanup-session',iat:Math.floor(Date.now()/1000)+1}
        await requestUserCleanup(customer.id,deletingActor)
        for(let retry=0;retry<40&&await prisma.user.findUnique({where:{id:customer.id}});retry++){
          if(retry)await requestUserCleanup(customer.id,deletingActor)
          await processUserCleanup(customer.id)
          if(await prisma.user.findUnique({where:{id:customer.id}}))await new Promise(resolve=>setTimeout(resolve,500))
        }
        assert.equal(await prisma.user.findUnique({where:{id:customer.id}}),null)
        assert.equal(await prisma.balanceLog.count({where:{userId:customer.id}}),0)
        assert.equal(await prisma.instanceBillingRecord.count({where:{userId:customer.id}}),0)
        await verifyInstanceDeleted(client,'cleanup-guest')
        assert.equal((await prisma.host.findUniqueOrThrow({where:{id:host.id}})).poolFaulted,false)
        console.log('PASS actual administrator account cleanup: running Incus guest/snapshot/volume/forward removed and pool resalable before wallet/bill/account deletion')
      } else if (process.env.EXPIRY_DELETION_WORKER === '1') {
        await prisma.host.update({ where: { id: host.id }, data: { poolFaulted: false } })
        const original = await client.request<{ created_at: string; config: Record<string, string> }>('GET', '/1.0/instances/cleanup-guest')
        const pkg = await prisma.package.create({ data: { userId: actor.id, name: 'actual-expiry', cpuMax: 200, memoryMax: 768, diskMax: 30720 } })
        const plan = await prisma.packagePlan.create({ data: { packageId: pkg.id, name: 'actual-expiry', cpu: 200, memory: 768, disk: 30720,
          portLimit: 0, snapshotLimit: 0, backupLimit: 0, siteLimit: 0, trafficLimit: 0n, price: 10 } })
        const instance = await prisma.instance.create({ data: { userId: actor.id, hostId: host.id, name: 'cleanup-guest', incusId: 'cleanup-guest',
          image: 'cleanup-fixture', status: 'running', cpu: host.cpuAllowanceMax, memory: host.memoryMax, disk: 30720, storagePoolName: 'cleanup-test',
          packageId: pkg.id, packagePlanId: plan.id, billingPrice: 10, billingCycle: 1, expiresAt: new Date(Date.now() - 60000),
          snapshottedSpecs: { recoveryIdentity: { uuid: original.config['volatile.uuid'], createdAt: original.created_at, project: 'default' } } } })
        await executeExpiryEnforcement()
        assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: instance.id } })).status, 'suspended')
        assert.equal((await client.request<{status:string}>('GET','/1.0/instances/cleanup-guest')).status, 'Stopped')
        await prisma.instance.update({ where: { id: instance.id }, data: { expiresAt: new Date(Date.now() - 4 * 86400000), suspendedAt: new Date(Date.now() - 4 * 86400000) } })
        await executeExpiryEnforcement()
        const deleted = await prisma.instance.findUniqueOrThrow({ where: { id: instance.id } })
        assert.equal(deleted.status, 'deleted'); assert.equal(deleted.deletionBillingPending, false)
        await verifyInstanceDeleted(client, 'cleanup-guest')
        await prisma.instance.delete({ where: { id: instance.id } }); await prisma.package.delete({ where: { id: pkg.id } })
        console.log('PASS actual five-minute expiry path: Incus Stopped -> retention cutoff -> container/snapshot/disk/forward deleted -> pool released')
      } else if (process.env.INSTANCE_DELETION_WORKER === '1') {
        await prisma.host.update({ where: { id: host.id }, data: { poolFaulted: false } })
        const instance = await prisma.instance.create({ data: { userId: actor.id, hostId: host.id, name: 'cleanup-guest', incusId: 'cleanup-guest',
          image: 'cleanup-fixture', status: 'running', cpu: host.cpuAllowanceMax, memory: host.memoryMax, disk: 30720, storagePoolName: 'cleanup-test' } })
        const result = await requestInstanceDeletion(instance, { id: actor.id, sid: 'disposable-ci-session', iat: Math.floor(Date.now() / 1000) }, { mode: 'admin' })
        assert.equal(result.success, true, JSON.stringify(result))
        const deleted = await prisma.instance.findUniqueOrThrow({ where: { id: instance.id } })
        assert.equal(readDeletionIntent(deleted.deletionIntent)?.status, 'done')
        assert.equal(deleted.deletionBillingPending, false)
        assert.equal(await prisma.balanceLog.count({ where: { instanceId: instance.id } }), 0)
        // Completed deletion must wake recovery itself, without the scanner or
        // a test manually executing the recovery worker.
        for (let check = 0; check < 200 && (await prisma.host.findUniqueOrThrow({ where: { id: host.id } })).poolFaulted; check++) {
          await new Promise(resolve => setTimeout(resolve, 100))
        }
        assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: host.id } })).poolFaulted, false)
        console.log('PASS actual durable instance deletion: persisted UUID, running guest/snapshot/forward deletion, PostgreSQL allocation settlement and automatic sale readiness')
      } else {
      await prisma.host.update({ where: { id: host.id }, data: { poolCleanup: poolCleanupRecord(host, 'cleanup-guest', actor.id, new Date(), 1) } })
      // All remote calls use the actual pinned Incus client. Only the disposable
      // inventory/heartbeat metadata is seeded; no remote response is mocked.
      await processPoolCleanup(host.id, async () => client)
      }
      const result = await prisma.host.findUniqueOrThrow({ where: { id: host.id } })
      assert.equal(readPoolCleanup(result.poolCleanup)?.status, 'done', JSON.stringify(result.poolCleanup))
      assert.deepEqual([result.poolFaulted, result.cpuUsed, result.memoryUsed, result.diskUsed], [false, 0, 0, 0])
      assert.equal(await prisma.host.count({ where: { ...dedicatedHostReadyWhere(), id: host.id,
        instances: { none: HOST_OCCUPIED_INSTANCE_WHERE } } }), 1)
      console.log('PASS actual cleanup worker: persisted task, remote stop/delete and disk/forward confirmation, PostgreSQL inventory release')
    } finally {
      await prisma.instance.deleteMany({ where: { hostId: host.id } })
      await prisma.host.delete({ where: { id: host.id } })
      await prisma.user.delete({ where: { id: actor.id } })
    }
  } else {
    await stopInstance(client, 'cleanup-guest', true)
    await deleteInstance(client, 'cleanup-guest')
  }
  await verifyInstanceDeleted(client, 'cleanup-guest')
  const volumes = await client.request<Array<{ name: string; type: string }>>('GET', '/1.0/storage-pools/cleanup-test/volumes?recursion=1&all-projects=true')
  assert.ok(volumes.every(row => row.type === 'image'), 'no guest disk or snapshot remains allocated')
  assert.equal((await client.request<unknown[]>('GET', '/1.0/networks/incusbr0/forwards?recursion=1')).length, 0)
  console.log('PASS actual Incus mTLS deletion path: running guest stopped, deleted, system volume/snapshot/forward absent')
} finally { await client.close(); await closePrismaDatabase() }
process.exit(0)
