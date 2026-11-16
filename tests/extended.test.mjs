import test from 'node:test';import assert from 'node:assert/strict';
import {POLICY} from '../engine/policy.mjs';
import {scan} from '../engine/scanner.mjs';
import {cspStrength,permissionsPolicy,infoDisclosure,thirdPartyScripts,formTargets,securityTxt,sensitiveFiles,corsCheck,spfCheck,dmarcCheck,caaCheck,dnssecCheck,CORS_TEST_ORIGIN} from '../engine/extended.mjs';
const H=o=>new Headers(o);
const txt=(...v)=>({Status:0,Answer:v.map(d=>({type:16,data:`"${d}"`}))});

test('CSP strength flags missing script-src, unsafe-inline and wildcards; accepts a strict policy',()=>{
  assert.equal(cspStrength(H()).status,'Not tested');
  assert.equal(cspStrength(H({'content-security-policy':"frame-ancestors 'self'; object-src 'none'; base-uri 'self'"})).status,'Review');
  assert.equal(cspStrength(H({'content-security-policy':"script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'"})).status,'Review');
  assert.equal(cspStrength(H({'content-security-policy':"script-src https:; object-src 'none'; base-uri 'self'"})).status,'Review');
  assert.equal(cspStrength(H({'content-security-policy':"script-src 'self' 'nonce-abc'; object-src 'none'; base-uri 'self'"})).status,'Observed');
});
test('permissions policy and technology disclosure',()=>{
  assert.equal(permissionsPolicy(H()).status,'Review');assert.equal(permissionsPolicy(H({'permissions-policy':'camera=()'})).status,'Observed');
  assert.equal(infoDisclosure(H({server:'cloudflare'})).status,'Observed');
  assert.equal(infoDisclosure(H({server:'nginx/1.18.0'})).status,'Review');
  assert.equal(infoDisclosure(H({'x-powered-by':'Express'})).status,'Review');
  assert.equal(infoDisclosure(H(),'<meta name="generator" content="WordPress 6.4">').status,'Review');
});
test('third-party scripts need SRI; same-host scripts are ignored',()=>{
  assert.equal(thirdPartyScripts('<script src="/a.js"></script>',POLICY.host).status,'Observed');
  assert.equal(thirdPartyScripts('<script src="https://cdn.example/x.js"></script>',POLICY.host).status,'Review');
  assert.equal(thirdPartyScripts('<script src="https://cdn.example/x.js" integrity="sha384-x" crossorigin="anonymous"></script>',POLICY.host).status,'Observed');
});
test('forms posting to http are flagged',()=>{
  assert.equal(formTargets('<form action="http://x.example/p"></form>',POLICY.host).status,'Review');
  assert.equal(formTargets('<form action="/login"></form>',POLICY.host).status,'Observed');
});
test('security.txt: HTML fallback pages do not count; expired is flagged',()=>{
  assert.equal(securityTxt({status:200,contentType:'text/html',text:'<html>'}).status,'Review');
  assert.equal(securityTxt({status:404,contentType:'',text:''}).status,'Review');
  assert.equal(securityTxt({status:200,contentType:'text/plain',text:'Contact: mailto:a@b.c\nExpires: 2099-01-01T00:00:00Z'}).status,'Observed');
  assert.equal(securityTxt({status:200,contentType:'text/plain',text:'Contact: mailto:a@b.c\nExpires: 2001-01-01T00:00:00Z'}).status,'Review');
});
test('exposed files need a real signature, so SPA fallbacks are not false positives, and contents are never shown',()=>{
  const spa={status:200,contentType:'text/html',text:'<html>app</html>'};
  assert.equal(sensitiveFiles(spa,spa).status,'Observed');
  const c=sensitiveFiles({status:200,contentType:'text/plain',text:'ref: refs/heads/main\n'},{status:200,contentType:'text/plain',text:'API_KEY=supersecret\n'});
  assert.equal(c.status,'Review');assert.ok(!JSON.stringify(c).includes('supersecret'));assert.ok(!JSON.stringify(c).includes('refs/heads/main'));
});
test('CORS reflects-origin is flagged, wildcard on public page is not',()=>{
  assert.equal(corsCheck({headers:H({'access-control-allow-origin':CORS_TEST_ORIGIN,'access-control-allow-credentials':'true'})}).severity,'high');
  assert.equal(corsCheck({headers:H({'access-control-allow-origin':'*'})}).status,'Observed');
  assert.equal(corsCheck({headers:H()}).status,'Observed');
});
test('SPF, DMARC, CAA and DNSSEC parsing',()=>{
  assert.equal(spfCheck(txt('google-site-verification=abc')).status,'Review');
  assert.equal(spfCheck(txt('v=spf1 include:_spf.google.com ~all')).status,'Observed');
  assert.equal(spfCheck(txt('v=spf1 +all')).status,'Review');
  assert.equal(spfCheck(txt('v=spf1 a','v=spf1 mx ~all')).status,'Review');
  assert.equal(spfCheck(null).status,'Not tested');
  assert.equal(dmarcCheck({Status:3}).status,'Review');
  assert.equal(dmarcCheck(txt('v=DMARC1; p=none')).status,'Review');
  assert.equal(dmarcCheck(txt('v=DMARC1; p=reject; rua=mailto:a@b.c')).status,'Observed');
  assert.equal(caaCheck({Status:0}).status,'Review');assert.equal(caaCheck({Status:0,Answer:[{type:257,data:'0 issue "letsencrypt.org"'}]}).status,'Observed');
  assert.equal(dnssecCheck({AD:true}).status,'Observed');assert.equal(dnssecCheck({AD:false}).status,'Review');
});
test('extended scan stays on the fixed host and fixed paths, within budget',async()=>{
  const urls=[];const p={...POLICY,minIntervalMs:0,totalTimeoutMs:3000,requestTimeoutMs:500};
  const fetcher=async(u,o)=>{urls.push([u,o?.headers?.Origin]);
    if(u.startsWith('https://dns.google'))return Response.json({Status:0,AD:false,Answer:[]});
    if(u==='http://atlasclipping.com/')return new Response(null,{status:301,headers:{location:'https://atlasclipping.com/'}});
    if(u.endsWith('/.well-known/security.txt')||u.endsWith('/.git/HEAD')||u.endsWith('/.env'))return new Response('<html>spa</html>',{headers:{'content-type':'text/html'}});
    return new Response('<html></html>',{headers:{'content-type':'text/html'}})};
  const r=await scan({checkDNS:false,extended:true,policy:p,fetcher});
  assert.equal(r.status,'completed');
  const web=urls.filter(([u])=>!u.startsWith('https://dns.google'));
  assert.ok(web.length<=p.maxRequests);assert.equal(r.requestCount,web.length);
  for(const [u] of web)assert.ok(new URL(u).hostname===POLICY.host);
  assert.deepEqual(web.map(([u])=>new URL(u).pathname).filter(x=>x!=='/').sort(),['/.env','/.git/HEAD','/.well-known/security.txt']);
  assert.equal(web.filter(([,o])=>o).length,1);
  for(const id of ['csp-strength','security-txt','sensitive-files','cors','spf','dmarc','caa','dnssec'])assert.ok(r.checks.some(c=>c.id===id),id);
});
test('a 5xx on a probe path stops the scan without retries',async()=>{
  let n=0;const p={...POLICY,minIntervalMs:0,totalTimeoutMs:3000,requestTimeoutMs:500};
  const r=await scan({checkDNS:false,extended:true,policy:p,fetcher:async u=>{n++;if(u.endsWith('security.txt'))return new Response('',{status:503});if(u.startsWith('http://'))return new Response(null,{status:301,headers:{location:'https://atlasclipping.com/'}});return new Response('<html></html>',{headers:{'content-type':'text/html'}})}});
  assert.equal(r.status,'incomplete');assert.equal(r.error.code,'health_pause');assert.equal(n,3);
});
test('default scan (extended off) is unchanged: no extra requests',async()=>{
  let n=0;const p={...POLICY,minIntervalMs:0};
  await scan({checkDNS:false,policy:p,fetcher:async u=>{n++;return u.startsWith('http:')?new Response(null,{status:301,headers:{location:'https://atlasclipping.com/'}}):new Response('<html></html>',{headers:{'content-type':'text/html'}})}});
  assert.equal(n,2);
});
