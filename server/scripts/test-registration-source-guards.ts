import assert from 'node:assert/strict'
import { registrationSource } from '../src/lib/registration-source.js'
assert.deepEqual(registrationSource('::ffff:203.0.113.4'), registrationSource('203.0.113.4'))
assert.deepEqual(registrationSource('::FFFF:cb00:7104'), registrationSource('203.0.113.4'))
assert.deepEqual(registrationSource('0:0:0:0:0:ffff:cb00:7104'), registrationSource('203.0.113.4'))
assert.equal(registrationSource('2001:db8:abcd:1234::1').source,registrationSource('2001:0db8:abcd:1234:ffff:ffff:ffff:ffff').source)
assert.notEqual(registrationSource('2001:db8:abcd:1235::1').source,registrationSource('2001:db8:abcd:1234::1').source)
for(const value of ['unknown','1.2.3.4, 5.6.7.8','[::1]','fe80::1%eth0'])assert.throws(()=>registrationSource(value))
console.log('PASS registration source: IPv4-mapped normalization, IPv6 /64 rotation, malformed source refused')
