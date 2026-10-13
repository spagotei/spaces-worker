/* Privacy-minimized D1 security counters. Never log raw identifiers, IPs, tokens or passwords. */
const enc=new TextEncoder();
async function fingerprint(env,request,principal='') {
  const key=String(env.SECURITY_AUDIT_KEY||'');
  if(key.length<24)return 'not-configured';
  const ip=request.headers.get('CF-Connecting-IP')||'';
  const secret=await crypto.subtle.importKey('raw',enc.encode(key),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const sig=await crypto.subtle.sign('HMAC',secret,enc.encode(ip+'\0'+principal.toLowerCase().slice(0,180)));
  return Array.from(new Uint8Array(sig)).map(x=>x.toString(16).padStart(2,'0')).join('').slice(0,32);
}
async function write(env,request,kind,status,principal='') {
  try {
    const f=await fingerprint(env,request,principal);
    const now=Date.now();
    const bucket=Math.floor(now/300000);
    const eventKey=`${kind}:${status}:${bucket}:${f}`;
    await env.DB.prepare(`INSERT INTO security_event_counters_v85
      (event_key,kind,status,principal_fingerprint,first_seen,last_seen,event_count)
      VALUES (?,?,?,?,?,?,1)
      ON CONFLICT(event_key) DO UPDATE SET last_seen=excluded.last_seen,event_count=event_count+1`)
      .bind(eventKey,kind,status,f,now,now).run();
  } catch(error) {console.warn('Security counter unavailable',error instanceof Error?error.name:'unknown');}
}
export async function recordFailedLoginV85(env,request,identifier){await write(env,request,'login_failed',401,identifier)}
export async function recordStaffDeniedV85(env,request,status){await write(env,request,'staff_center_denied',status)}
