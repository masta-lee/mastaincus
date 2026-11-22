import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { AGENT_PUBLISHER_PUBLIC_KEY } from './agent-package-signature.mjs'

export const panelMessage = (version, architecture, hash) => Buffer.from(`payincus/panel-package/v1\n${version.replace(/^v/, '')}\nlinux-${architecture}\n${hash}`)
export function verifyPanelDigest(version, architecture, hash, signature, publicKey = AGENT_PUBLISHER_PUBLIC_KEY) {
  if (!/^(?:v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?|preview-[a-f0-9]{7})$/.test(version) || !['amd64','arm64'].includes(architecture) || !/^[a-f0-9]{64}$/.test(hash) || !/^[A-Za-z0-9+/]{86}==$/.test(signature || '')) return false
  const key = createPublicKey({format:'der',type:'spki',key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(publicKey,'base64')])})
  return verify(null,panelMessage(version,architecture,hash),key,Buffer.from(signature,'base64'))
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [file, version, architecture] = process.argv.slice(2)
  const key=createPrivateKey(await readFile(process.env.PANEL_PACKAGE_SIGNING_KEY_PATH))
  const publicKey=createPublicKey(key).export({format:'der',type:'spki'}).subarray(12).toString('base64')
  if(publicKey!==AGENT_PUBLISHER_PUBLIC_KEY)throw Error('Panel package publisher identity mismatch')
  const hash=createHash('sha256').update(await readFile(file)).digest('hex')
  const signature=sign(null,panelMessage(version,architecture,hash),key).toString('base64')
  if(!verifyPanelDigest(version,architecture,hash,signature))throw Error('Panel publisher signature invalid')
  await writeFile(file+'.sig',signature+'\n')
  console.log('Signed exact panel package with retained publisher identity')
}
