import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
import { resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

export const AGENT_PUBLISHER_PUBLIC_KEY = 'y6C9aLon6OtgHPp5KPVDpxoNha95YptW03o4Dp2djQA='
export const signatureMessage = (version, architecture, binary) => Buffer.from(`payincus/agent-package/v1\n${version.replace(/^v/, '')}\nlinux-${architecture}\n${createHash('sha256').update(binary).digest('hex')}`)
export function verifyAgentPackage(binary, version, architecture, signature) {
  const key = createPublicKey({ format:'der',type:'spki',key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(AGENT_PUBLISHER_PUBLIC_KEY,'base64')]) })
  return typeof signature === 'string' && /^[A-Za-z0-9+/]{86}==$/.test(signature) && verify(null,signatureMessage(version,architecture,binary),key,Buffer.from(signature,'base64'))
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const directory=resolve(process.argv[2]), keyPath=process.env.AGENT_PACKAGE_SIGNING_KEY_PATH
  if(!keyPath)throw Error('Agent package publisher signing key is required')
  const privateKey=createPrivateKey(await readFile(keyPath))
  if(privateKey.asymmetricKeyType!=='ed25519'||createPublicKey(privateKey).export({format:'der',type:'spki'}).subarray(12).toString('base64')!==AGENT_PUBLISHER_PUBLIC_KEY)throw Error('Agent publisher identity mismatch')
  const version=(await readFile(resolve(fileURLToPath(new URL('..',import.meta.url)),'agent/VERSION'),'utf8')).trim()
  const manifest={version,sourceCommit:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),files:{}}
  for(const architecture of ['amd64','arm64']) {
    const binary=await readFile(resolve(directory,`incudal-agent-linux-${architecture}`))
    if(binary.readUInt16LE(18)!==(architecture==='amd64'?62:183))throw Error('Agent ELF architecture mismatch')
    const signature=sign(null,signatureMessage(version,architecture,binary),privateKey).toString('base64')
    if(!verifyAgentPackage(binary,version,architecture,signature))throw Error('Agent publisher verification failed')
    manifest.files[`linux-${architecture}`]={architecture,binarySha256:createHash('sha256').update(binary).digest('hex'),signature}
  }
  await writeFile(resolve(directory,'publisher-manifest.json'),JSON.stringify(manifest))
  console.log('Signed both Agent architectures with retained publisher identity')
}
