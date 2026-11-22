import assert from 'node:assert/strict'
import {createServer} from 'node:http'
import {readFile,stat} from 'node:fs/promises'
import {resolve,extname,sep} from 'node:path'
import {Browser,sleep} from '../.agents/skills/design-taste-frontend/scripts/lib/cdp.mjs'
const root=resolve(import.meta.dirname,'..'),template=await readFile(resolve(root,'deploy/nginx-split-intranet.conf.example'),'utf8')
const policies=[...template.matchAll(/add_header Content-Security-Policy "([^"\n]+)" always;/g)].map(match=>match[1])
assert.equal(policies.length,2);assert.ok(policies.every(policy=>!policy.split(';').find(rule=>rule.trim().startsWith('script-src')).includes('unsafe-inline')))
const servers=[];let browser
const mime={'.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.json':'application/json','.webp':'image/webp','.woff2':'font/woff2'}
try {
  browser=await Browser.launch()
  for(const [index,entry]of ['user','admin'].entries()) {
    const directory=resolve(root,'client/dist',entry)
    const server=createServer(async(request,response)=>{
      response.setHeader('Content-Security-Policy',policies[index]);response.setHeader('Cache-Control','no-store')
      const path=new URL(request.url,'http://fixture.invalid').pathname
      if(path.startsWith('/api/')){response.setHeader('Content-Type','application/json');response.end(JSON.stringify(path.endsWith('/public')||path.includes('/config')?{success:true,data:{brand_name:'Incudal',turnstile_enabled:false}}:{data:[],success:true}));return}
      try {
        const file=resolve(directory,'.'+decodeURIComponent(path));assert.ok(file===directory||file.startsWith(directory+sep))
        const target=(await stat(file).catch(()=>null))?.isFile()?file:resolve(directory,'index.html')
        response.setHeader('Content-Type',mime[extname(target)]||'application/octet-stream');response.end(await readFile(target))
      }catch{response.writeHead(404);response.end()}
    });servers.push(server);await new Promise(done=>server.listen(0,'127.0.0.1',done))
    const port=server.address().port
    for(const locale of ['zh-CN','zh-TW','en']) {
      const page=await browser.newPage({reducedMotion:true})
      await page.send('Page.addScriptToEvaluateOnNewDocument',{source:`localStorage.setItem('locale',${JSON.stringify(locale)});window.cspViolations=[];document.addEventListener('securitypolicyviolation',event=>window.cspViolations.push({directive:event.effectiveDirective,blocked:event.blockedURI}));`})
      await page.goto(`http://127.0.0.1:${port}/login`,{settleMs:1000})
      for(let deadline=Date.now()+10000;!await page.eval(()=>document.querySelectorAll('input').length>=2);){assert.ok(Date.now()<deadline,`${entry} login did not load`);await sleep(100)}
      assert.equal(await page.eval(()=>document.documentElement.classList.contains('light')||document.documentElement.classList.contains('dark')),true)
      assert.deepEqual(await page.eval(()=>window.cspViolations.filter(event=>/script|style/.test(event.directive))),[],`${entry}/${locale} shipped login script and styles comply with actual header`)
      await page.eval(()=>{const script=document.createElement('script');script.textContent='window.inlineAttackRan=true';document.head.append(script)})
      assert.equal(await page.eval(()=>window.inlineAttackRan===true),false)
      console.log(`PASS Chrome shipped ${entry}/${locale}: login controls/theme load, script/style CSP clean, inline injection blocked`)
    }
  }
}finally{if(browser)await browser.close();for(const server of servers){server.closeAllConnections();await new Promise(done=>server.close(done))}}
