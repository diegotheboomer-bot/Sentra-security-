// Extended checks. Pure analyzers: they take already-fetched responses and return check objects.
// Nothing here makes a request or sends a payload.
import {redactURL} from './checks.mjs';

const check=(id,name,status,summary,evidence,fix,severity,category)=>({id,name,status,summary,evidence,fix,severity,category,confidence:'Response observation'});
const parseDirectives=csp=>Object.fromEntries(csp.split(';').map(s=>s.trim()).filter(Boolean).map(s=>{const [k,...v]=s.split(/\s+/);return [k.toLowerCase(),v.join(' ')]}));
function tags(html,name){const out=[];for(const m of html.matchAll(new RegExp(`<${name}\\b[^>]*>`,'gi'))){const attrs={};for(const a of m[0].matchAll(/([\w-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g))attrs[a[1].toLowerCase()]=a[2]??a[3]??a[4];attrs._raw=m[0];out.push(attrs)}return out}

// ---- Passive checks on the homepage response (no extra requests) ----

export function cspStrength(headers){
  const csp=headers.get('content-security-policy');
  if(!csp)return check('csp-strength','CSP strength','Not tested','There is no enforcing CSP header to evaluate.','Content-Security-Policy header absent.','Add a Content Security Policy first; this check then reviews how strict it is.','medium','Browser protections');
  const d=parseDirectives(csp),script=d['script-src']??d['default-src'],issues=[];
  if(script===undefined)issues.push('No script-src or default-src. This policy does not restrict which scripts can run, so it gives little protection against injected scripts.');
  else{
    const protectedInline=/'nonce-|'sha(?:256|384|512)-|'strict-dynamic'/.test(script);
    if(/'unsafe-inline'/.test(script)&&!protectedInline)issues.push("script-src allows 'unsafe-inline' without a nonce or hash.");
    if(/'unsafe-eval'/.test(script))issues.push("script-src allows 'unsafe-eval'.");
    if(/(^|\s)(\*|https?:|data:)(\s|$)/.test(script))issues.push('script-src allows a wildcard or an entire scheme (*, http:, https: or data:).');
  }
  if(d['object-src']===undefined&&d['default-src']===undefined)issues.push('No object-src or default-src; plugin content is not restricted.');
  if(d['base-uri']===undefined)issues.push('No base-uri; injected <base> tags are not restricted.');
  const bad=issues.length>0;
  return check('csp-strength','CSP strength',bad?'Review':'Observed',bad?`The policy exists but has ${issues.length} weakness${issues.length===1?'':'es'}.`:'No common weaknesses were found in the CSP.',bad?issues.join('\n'):'script-src is restricted; no unsafe-inline, unsafe-eval or wildcard sources found.','Add a script-src (or default-src) listing only the origins you use, prefer nonces or hashes over unsafe-inline, and add base-uri \'self\'. Test in report-only mode first so nothing breaks. A strict policy reduces the impact of XSS; it does not prove XSS is absent.','medium','Browser protections');
}

export function permissionsPolicy(headers){
  const v=headers.get('permissions-policy')||headers.get('feature-policy');
  return check('permissions','Permissions Policy',v?'Observed':'Review',v?'A Permissions-Policy header was observed.':'No Permissions-Policy header was observed.',v?v.slice(0,400):'Permissions-Policy header absent.','Add a Permissions-Policy that turns off browser features the site does not use, for example: camera=(), microphone=(), geolocation=(). This limits what injected or embedded third-party code can access.','low','Browser protections');
}

export function infoDisclosure(headers,html=''){
  const found=[];
  const server=headers.get('server')||'';if(/\d+\.\d+/.test(server))found.push('Server: '+server.slice(0,120));
  for(const n of ['x-powered-by','x-aspnet-version','x-aspnetmvc-version','x-generator'])if(headers.get(n))found.push(`${n}: ${headers.get(n).slice(0,120)}`);
  const gen=tags(html,'meta').find(m=>(m.name||'').toLowerCase()==='generator'&&/\d+\.\d+/.test(m.content||''));if(gen)found.push('meta generator: '+gen.content.slice(0,120));
  const bad=found.length>0;
  return check('disclosure','Technology disclosure',bad?'Review':'Observed',bad?'The response advertises software names or versions.':'No software version details were found in headers or generator tags.',bad?found.join('\n'):`Server: ${server||'not disclosed'}`,'Remove or generalize version-bearing headers such as Server, X-Powered-By and generator tags. Hiding versions is not a substitute for patching, but it makes automated targeting harder.','low','Information exposure');
}

export function thirdPartyScripts(html,host,truncated=false){
  const external=[];
  for(const s of tags(html,'script')){
    if(!s.src)continue;let u;try{u=new URL(s.src,'https://'+host+'/')}catch{continue}
    if(u.hostname===host)continue;
    external.push({origin:u.hostname,url:redactURL(u.href),sri:Boolean(s.integrity)});
  }
  const origins=[...new Set(external.map(e=>e.origin))];
  const noSri=external.filter(e=>!e.sri);
  if(!external.length)return check('third-party','Third-party scripts','Observed','No third-party scripts were found in the inspected HTML.',`Inspected up to 256 KiB of HTML${truncated?' (truncated)':''}. Scripts loaded dynamically are not visible here.`,'Keep third-party script use minimal. Any script you load can run with full access to your page.','medium','Supply chain');
  const bad=noSri.length>0;
  return check('third-party','Third-party scripts',bad?'Review':'Observed',bad?`${noSri.length} third-party script${noSri.length===1?' is':'s are'} loaded without Subresource Integrity.`:'All third-party scripts declare Subresource Integrity.',`Origins: ${origins.slice(0,10).join(', ')}\n`+external.slice(0,10).map(e=>`${e.sri?'SRI    ':'no SRI '} ${e.url}`).join('\n'),'Add integrity="sha384-…" and crossorigin="anonymous" to static third-party scripts so a compromised CDN cannot silently change them. Scripts that must update dynamically (some analytics tags) cannot use SRI; review those separately.','medium','Supply chain');
}

export function formTargets(html,host,truncated=false){
  const bad=[];let forms=0;
  for(const f of tags(html,'form')){forms++;const a=(f.action||'').trim();if(/^http:\/\//i.test(a))bad.push(redactURL(a))}
  const pw=/<input\b[^>]*type\s*=\s*["']?password/i.test(html);
  const isBad=bad.length>0;
  return check('forms','Form targets',isBad?'Review':'Observed',isBad?'A form on the page submits to an insecure http:// address.':forms?`${forms} form${forms===1?'':'s'} found; none submit to http://.`:'No forms were found on the homepage.',isBad?bad.join('\n'):`Forms: ${forms}; password field on homepage: ${pw?'yes':'no'}${truncated?' (HTML truncated)':''}`,'Submit forms only to https:// addresses (or relative URLs on an HTTPS page). Data sent over http:// can be read or changed in transit.','high','Browser protections');
}

// ---- Fixed-path probes (each is one read-only GET to a known path) ----

export const PROBE_PATHS=Object.freeze({securityTxt:'/.well-known/security.txt',git:'/.git/HEAD',env:'/.env'});
export const CORS_TEST_ORIGIN='https://sentra-origin-check.invalid';

export function securityTxt(res){
  const present=res&&res.status===200&&!/text\/html/i.test(res.contentType||'')&&/^\s*contact\s*:/im.test(res.text||'');
  if(!present)return check('security-txt','security.txt','Review','No valid /.well-known/security.txt was found.',`GET ${PROBE_PATHS.securityTxt}\nHTTP ${res?.status??'n/a'}${res&&/text\/html/i.test(res.contentType||'')?' (HTML page, not a security.txt file)':''}`,'Publish a security.txt (RFC 9116) with a Contact line and an Expires date so researchers know how to report problems to you. Optional, but it is the standard way to be reachable.','low','Information exposure');
  const exp=(res.text.match(/^\s*expires\s*:\s*(.+)$/im)||[])[1],date=exp?new Date(exp.trim()):null,expired=date&&!isNaN(date)&&date<new Date(),missing=!exp;
  const bad=expired||missing;
  return check('security-txt','security.txt',bad?'Review':'Observed',expired?'security.txt is present but expired.':missing?'security.txt is present but has no Expires field.':'A valid security.txt with a Contact and a current Expires date was found.',`GET ${PROBE_PATHS.securityTxt}\nHTTP 200\nExpires: ${exp?exp.trim().slice(0,60):'absent'}`,'Keep an Expires date in the future (a year ahead is typical) and review the file when you renew it.','low','Information exposure');
}

export function sensitiveFiles(git,env){
  const hits=[],lines=[];
  const gitHit=git&&git.status===200&&/^\s*ref:\s*refs\//m.test(git.text||'');
  const envHit=env&&env.status===200&&!/text\/html/i.test(env.contentType||'')&&/^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+/m.test(env.text||'');
  if(gitHit)hits.push(PROBE_PATHS.git);if(envHit)hits.push(PROBE_PATHS.env);
  lines.push(`${PROBE_PATHS.git}: HTTP ${git?.status??'n/a'}${gitHit?' (git metadata signature matched)':''}`,`${PROBE_PATHS.env}: HTTP ${env?.status??'n/a'}${envHit?' (environment-file signature matched)':''}`,'File contents are never stored or shown.');
  return check('sensitive-files','Exposed sensitive files',hits.length?'Review':'Observed',hits.length?`${hits.length} sensitive file${hits.length===1?' is':'s are'} publicly readable.`:'Neither /.git/HEAD nor /.env was publicly readable.',lines.join('\n'),hits.length?'Block public access to these paths now, then treat any secrets that could have been in them as compromised and rotate them. Exposed .git metadata can let others download your source code; an exposed .env often holds keys and passwords.':'Keep dotfiles and version-control folders out of your web root. This checks two common paths only; it is not a full content-discovery scan.',hits.length?'high':'low','Information exposure');
}

export function corsCheck(res){
  const acao=res.headers.get('access-control-allow-origin')||'',acac=(res.headers.get('access-control-allow-credentials')||'').toLowerCase()==='true';
  const reflected=acao===CORS_TEST_ORIGIN,wildcard=acao==='*';
  if(reflected)return check('cors','Cross-origin access (CORS)','Review',acac?'The site trusts any origin and allows credentials.':'The site reflects an arbitrary Origin in Access-Control-Allow-Origin.',`Sent Origin: ${CORS_TEST_ORIGIN}\nAccess-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,'Allow only a fixed list of trusted origins instead of echoing the request Origin. Never combine a reflected origin with Allow-Credentials: true. This was observed on the homepage only; check your API routes separately.',acac?'high':'medium','Browser protections');
  return check('cors','Cross-origin access (CORS)','Observed',wildcard?'The homepage allows any origin without credentials, which is normal for public content.':'An untrusted Origin was not reflected or allowed.',`Sent Origin: ${CORS_TEST_ORIGIN}\nAccess-Control-Allow-Origin: ${acao||'absent'}\nAccess-Control-Allow-Credentials: ${acac}`,'Keep CORS limited to a fixed list of trusted origins on any route that returns private data. Only the homepage was tested.','low','Browser protections');
}

// ---- Public DNS checks (data parsed from DNS-over-HTTPS JSON answers) ----

export const txtRecords=answer=>(answer?.Answer||[]).filter(a=>a.type===16).map(a=>String(a.data).replace(/"\s*"/g,'').replace(/^"|"$/g,''));

export function spfCheck(dns){
  if(!dns)return check('spf','Email spoofing: SPF','Not tested','DNS lookup did not complete.','No DNS answer.','Retry the check.','medium','Email & DNS');
  const spf=txtRecords(dns).filter(t=>/^v=spf1\b/i.test(t));
  if(!spf.length)return check('spf','Email spoofing: SPF','Review','No SPF record was found.','No TXT record starting with v=spf1.','Add an SPF TXT record listing the services that send email for your domain and ending in ~all or -all. If the domain sends no email, use "v=spf1 -all". Without SPF, anyone can more easily forge mail from your domain.','medium','Email & DNS');
  if(spf.length>1)return check('spf','Email spoofing: SPF','Review','More than one SPF record exists, which makes SPF invalid.',spf.join('\n').slice(0,500),'Merge them into a single v=spf1 record.','medium','Email & DNS');
  const r=spf[0],weak=/(^|\s)\+all\b|(^|\s)\?all\b/i.test(r)||!/[~-]all\b|redirect=/i.test(r);
  return check('spf','Email spoofing: SPF',weak?'Review':'Observed',weak?'The SPF record does not restrict who can send.':'An SPF record with a restrictive policy was found.',r.slice(0,500),'End the record with ~all or -all instead of +all, ?all or nothing. SPF is one half of email protection; DMARC is the other.','medium','Email & DNS');
}

export function dmarcCheck(dns){
  if(!dns)return check('dmarc','Email spoofing: DMARC','Not tested','DNS lookup did not complete.','No DNS answer.','Retry the check.','medium','Email & DNS');
  const d=txtRecords(dns).find(t=>/^v=DMARC1\b/i.test(t));
  if(!d)return check('dmarc','Email spoofing: DMARC','Review','No DMARC record was found.','No v=DMARC1 TXT record at _dmarc.','Add a DMARC record at _dmarc. Start with "v=DMARC1; p=none; rua=mailto:you@yourdomain" to watch who sends as you, then move to p=quarantine and p=reject.','medium','Email & DNS');
  const p=(d.match(/(?:^|;)\s*p\s*=\s*(\w+)/i)||[])[1]?.toLowerCase();
  const enforcing=['quarantine','reject'].includes(p);
  return check('dmarc','Email spoofing: DMARC',enforcing?'Observed':'Review',enforcing?`DMARC is enforcing (p=${p}).`:'DMARC exists but only monitors (p=none) or has no valid policy.',d.slice(0,500),'Review the DMARC reports, fix legitimate senders, then raise the policy to p=quarantine and finally p=reject so forged mail is blocked.','medium','Email & DNS');
}

export function caaCheck(dns){
  if(!dns)return check('caa','Certificate authority restriction (CAA)','Not tested','DNS lookup did not complete.','No DNS answer.','Retry the check.','low','Email & DNS');
  const recs=(dns.Answer||[]).filter(a=>a.type===257).map(a=>String(a.data));
  return check('caa','Certificate authority restriction (CAA)',recs.length?'Observed':'Review',recs.length?'CAA records limit which authorities may issue certificates.':'No CAA record was found.',recs.length?recs.join('\n').slice(0,400):'No CAA records.','Add CAA records naming only the certificate authorities you use (for example 0 issue "letsencrypt.org"). This limits who can issue a certificate for your domain.','low','Email & DNS');
}

export function dnssecCheck(dns){
  if(!dns)return check('dnssec','DNSSEC','Not tested','DNS lookup did not complete.','No DNS answer.','Retry the check.','low','Email & DNS');
  const ad=dns.AD===true;
  return check('dnssec','DNSSEC',ad?'Observed':'Review',ad?'The public resolver validated this domain with DNSSEC.':'The public resolver did not report DNSSEC validation for this domain.',`Resolver authenticated-data flag: ${ad}`,'Enable DNSSEC at your DNS host and add the DS record at your registrar. This helps prevent forged DNS answers. Some hosts make it a one-click setting.','low','Email & DNS');
}
