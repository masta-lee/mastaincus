import assert from 'node:assert/strict'
import { customerNotificationData, customerNotificationText } from '../src/lib/customer-notification.js'
import { getNotificationContent } from '../src/lib/notifier.js'
import { closePrismaDatabase } from '../src/db/prisma.js'
import { telegramMarkdownText, telegramHtmlText } from '../src/lib/telegram-format.js'
const data={instanceName:'customer-vps',hostName:'secret-host',oldHostName:'old-secret',newHostName:'new-secret',ociAccountName:'oci-owner-secret',ipv4:'10.10.3.14',ipv6:'fd42::12',error:'incus failed on secret-host OCI oci-owner-secret 10.10.3.14',amount:11,newImage:'debian/13'}
for(const type of ['instance_created','instance_started','instance_restarted','instance_rebuilt','instance_host_changed','instance_create_failed','instances_batch_extended','refund_completed'] as const){
 const result=getNotificationContent(type,data)
 assert.ok(!/secret-host|old-secret|new-secret|oci-owner-secret|10\.10\.3\.14|fd42|undefined/.test(result.message),type)
}
const clean=customerNotificationData({...data,ipv4:'203.0.113.14',ipv6:'2603:c020::1'})
assert.equal(clean.ipv4,'203.0.113.14');assert.equal(clean.ipv6,'2603:c020::1');assert.equal(clean.hostName,undefined)
assert.equal(customerNotificationText('实例正常\n节点: internal\nIPv4: public'),'实例正常\nIPv4: public')
const nested = customerNotificationData({meta:{host_name:'nested-secret-host',oci:{account_label:'nested-oci'}},message:'nested-secret-host nested-oci 10.3.2.1 ::1 fe80::1%eth0'})
assert.ok(!JSON.stringify(nested).includes('nested-secret-host'))
assert.ok(!JSON.stringify(nested).includes('nested-oci'))
assert.ok(!/10\.3\.2\.1|::1|fe80::1/.test(nested.message))
for (const char of ['_','\\','<','&','😀']) {
  const markdown = telegramMarkdownText(char.repeat(1000),char.repeat(10000))
  const html = telegramHtmlText(char.repeat(1000),char.repeat(10000))
  assert.ok(markdown.length<=4096 && html.length<=4096)
  assert.ok(!markdown.endsWith('\\'))
  assert.ok(!/[\uD800-\uDBFF]$/.test(markdown) && !/[\uD800-\uDBFF]$/.test(html))
}
assert.ok(telegramMarkdownText('Title','Body',{label:'Panel',url:'https://example.test/a)b'}).includes('a\\)b'))
assert.throws(()=>telegramMarkdownText('Title','Body',{label:'Panel',url:'javascript:alert(1)'}))
console.log('PASS customer lifecycle notifications exclude host/OCI/private network/raw errors and retain public addresses')
await closePrismaDatabase()
process.exit(0)
