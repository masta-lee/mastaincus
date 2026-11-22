import assert from 'node:assert/strict'
import { generateKeyPairSync, sign, createHash } from 'node:crypto'
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { panelMessage, verifyPanelDigest } from './panel-package-signature.mjs'

const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const key = publicKey.export({format:'der',type:'spki'}).subarray(12).toString('base64')
const payload = Buffer.from('isolated publisher package fixture')
const digest = createHash('sha256').update(payload).digest('hex')
for (const version of ['v1.8.15','preview-abc1234']) for (const architecture of ['amd64','arm64']) {
  const signature = sign(null,panelMessage(version,architecture,digest),privateKey).toString('base64')
  assert.ok(verifyPanelDigest(version,architecture,digest,signature,key))
  assert.equal(verifyPanelDigest(version,architecture,digest,signature),false)
  for (const changes of [['v2.0.0',architecture,digest],[version,architecture,'0'.repeat(64)],[version,architecture==='amd64'?'arm64':'amd64',digest]]) assert.equal(verifyPanelDigest(...changes,signature,key),false)
}
if (process.platform === 'linux') {
  const folder = await mkdtemp(join(tmpdir(),'publisher-install-'))
  try {
    const panel = await readFile(new URL('./install-panel.sh',import.meta.url),'utf8')
    const agent = await readFile(new URL('../server/templates/agent-install.sh',import.meta.url),'utf8')
    const fixed = 'y6C9aLon6OtgHPp5KPVDpxoNha95YptW03o4Dp2djQA='
    const extract = (source,name,next) => {
      const start=source.indexOf(name+'() {'),end=source.indexOf(next,start)
      assert.ok(start>=0&&end>start)
      const code=source.slice(start,end);assert.ok(code.includes(fixed)&&code.includes('openssl pkeyutl'))
      // Only the test publisher key is substituted; run the product's actual
      // shell parser, hashing and OpenSSL verification, with no crypto mocks.
      return code.replace(fixed,key)
    }
    const panelCode=extract(panel,'verify_release_publisher','# ========================== 扫描手动放置')
    const agentCode=extract(agent,'verify_publisher_signature','download_manifest()')
    const script=join(folder,'verify.sh')
    await writeFile(script,`#!/bin/bash\nset -eu\nerror(){ printf 'rejected\\n' >&2; }\nfail(){ exit 1; }\nsha256_file(){ sha256sum "$1" | awk '{print $1}'; }\n${panelCode}\n${agentCode}\nif [[ "$1" == panel ]]; then verify_release_publisher "$2"; else DRY_RUN=0; STAGED_BIN="$2"; BINARY_VERSION="$3"; ARCH="$4"; BINARY_SIGNATURE=$(cat "$2.sig"); verify_publisher_signature; fi\n`)
    const verify=(...args)=>spawnSync('/bin/bash',[script,...args],{encoding:'utf8',timeout:10000})
    for (const architecture of ['amd64','arm64']) for (const kind of ['panel','agent']) {
      const version=kind==='panel'?'preview-abc1234':'v1.0.17'
      const file=join(folder,kind==='panel'?`incudal-${version}-linux-${architecture}.tar.gz`:`agent-${architecture}`)
      const message=kind==='panel'?panelMessage(version,architecture,digest):Buffer.from(`payincus/agent-package/v1\n${version.slice(1)}\nlinux-${architecture}\n${digest}`)
      const signature=sign(null,message,privateKey).toString('base64')
      await writeFile(file,payload);await writeFile(file+'.sig',signature+'\n')
      const valid=verify(kind,file,version,architecture)
      assert.equal(valid.status,0,`${kind} ${architecture}: ${valid.error?.code||''} ${valid.stderr||''}`)
      await writeFile(file,Buffer.from('changed package'))
      assert.notEqual(verify(kind,file,version,architecture).status,0)
      await writeFile(file,payload);await writeFile(file+'.sig','A'.repeat(86)+'==\n')
      assert.notEqual(verify(kind,file,version,architecture).status,0)
      await writeFile(file+'.sig',signature+'\n')
      if(kind==='agent') {
        assert.notEqual(verify(kind,file,'v9.0.0',architecture).status,0)
        assert.notEqual(verify(kind,file,version,architecture==='amd64'?'arm64':'amd64').status,0)
      } else {
        const wrong=join(folder,`incudal-v9.0.0-linux-${architecture}.tar.gz`)
        await writeFile(wrong,payload);await writeFile(wrong+'.sig',signature+'\n')
        assert.notEqual(verify(kind,wrong).status,0)
      }
    }
    console.log('PASS actual installer shell/OpenSSL: both architectures, correct signature, changed bytes, wrong signature, version and architecture')
  } finally { await rm(folder,{recursive:true,force:true}) }
} else console.log('Native Linux validation required for actual shell/OpenSSL installer execution')
console.log('PASS publisher package signature cryptographic boundaries')
