import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { panelMessage, verifyPanelDigest } from './panel-package-signature.mjs'
const { publicKey, privateKey }=generateKeyPairSync('ed25519')
const key=publicKey.export({format:'der',type:'spki'}).subarray(12).toString('base64')
const hash=createHash('sha256').update('synthetic package').digest('hex')
for(const version of ['v1.8.15','preview-abc1234'])for(const arch of ['amd64','arm64']){
  const signature=sign(null,panelMessage(version,arch,hash),privateKey).toString('base64')
  assert.ok(verifyPanelDigest(version,arch,hash,signature,key))
  assert.equal(verifyPanelDigest(version,arch,hash,signature),false)
  assert.equal(verifyPanelDigest(version,arch,'0'.repeat(64),signature,key),false)
  assert.equal(verifyPanelDigest('v2.0.0',arch,hash,signature,key),false)
  assert.equal(verifyPanelDigest(version,arch==='amd64'?'arm64':'amd64',hash,signature,key),false)
}
console.log('PASS panel signature binds exact version, architecture, package hash and independent publisher')
