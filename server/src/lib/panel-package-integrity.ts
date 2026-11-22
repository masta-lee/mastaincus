import { createPublicKey, verify } from 'node:crypto'
// Frozen identities of the last two public unsigned packages. A checksum
// supplied by a remote release never adds another unsigned package to this set.
const legacy: Record<string,string> = {
  'incudal-v1.8.13-linux-amd64.tar.gz':'f4b1e4274d7d9d3beeff775346bac900a540d47eb57d6a9c4d24cefed7bd6d84',
  'incudal-v1.8.13-linux-arm64.tar.gz':'d9114de77354731f8385a302ddb3c549a7617c738eaa85f2705326e0c37e072b',
  'incudal-v1.8.14-linux-amd64.tar.gz':'9cfd05408aa6ddd0ec0d7872099c2a0b550d96bce2beb2a063f220f55dd85ee4',
  'incudal-v1.8.14-linux-arm64.tar.gz':'03bfb27d636d628048761a44e3bdca8f5d55b1f33183e2466465dfdd98657eaf'
}
const publisher=createPublicKey({format:'der',type:'spki',key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from('y6C9aLon6OtgHPp5KPVDpxoNha95YptW03o4Dp2djQA=','base64')])})
export function verifyPanelPackageIdentity(artifact:{name:string;arch:string;sha256:string;signature?:string;version?:string}) {
  if(legacy[artifact.name]===artifact.sha256 && !artifact.signature && artifact.name.endsWith(`-linux-${artifact.arch}.tar.gz`) && (!artifact.version||artifact.name===`incudal-${artifact.version}-linux-${artifact.arch}.tar.gz`))return true
  const version=artifact.version||'',signature=artifact.signature||''
  if(!/^(?:v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?|preview-[a-f0-9]{7})$/.test(version)||!['amd64','arm64'].includes(artifact.arch)||artifact.name!==`incudal-${version}-linux-${artifact.arch}.tar.gz`||!/^[a-f0-9]{64}$/.test(artifact.sha256)||!/^[A-Za-z0-9+/]{86}==$/.test(signature))return false
  return verify(null,Buffer.from(`payincus/panel-package/v1\n${version.replace(/^v/,'')}\nlinux-${artifact.arch}\n${artifact.sha256}`),publisher,Buffer.from(signature,'base64'))
}
