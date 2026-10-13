import PostalMime from 'postal-mime';

const MAX_RAW = 2 * 1024 * 1024;
const MAX_TEXT = 100000;
const MAILBOXES = new Set(['support@yourspaces.net', 'hello@yourspaces.net']);
const clean = (value, limit) => String(value ?? '').replace(/[\u0000-\u001f\u007f]/gu, ' ').trim().slice(0, limit);
const literal = value => '%' + value.replace(/[\\%_]/gu, '\\$&') + '%';
const privateResponse = response => {
  const result = new Response(response.body, response);
  result.headers.set('Cache-Control', 'private, no-store, max-age=0');
  result.headers.set('Pragma', 'no-cache');
  result.headers.set('Vary', 'Origin, Authorization, X-Spaces-Developer-Mode');
  result.headers.set('X-Content-Type-Options', 'nosniff');
  return result;
};

async function readBounded(stream) {
  const reader = stream.getReader();
  const chunks = []; let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RAW) { await reader.cancel(); return null; }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(total); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}

function plainHtml(html) {
  // The result is only ever rendered as React text. This is not an HTML sanitizer.
  return String(html ?? '').replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/giu, '')
    .replace(/<(?:br|\/p|\/div|\/li|\/h[1-6])\b[^>]*>/giu, '\n')
    .replace(/<[^>]*>/gu, '').replace(/&nbsp;/gu, ' ').replace(/&lt;/gu, '<')
    .replace(/&gt;/gu, '>').replace(/&quot;/gu, '"').replace(/&#39;/gu, "'").replace(/&amp;/gu, '&').trim();
}

/** Only the Cloudflare email event calls this. There is no HTTP ingest endpoint. */
export async function receiveStaffEmail(message, env) {
  const recipient = String(message.to ?? '').trim().toLowerCase();
  if (!MAILBOXES.has(recipient)) { message.setReject('This address is not a Spaces support mailbox.'); return; }
  if (Number(message.rawSize) > MAX_RAW) { message.setReject('Message too large. Send at most 2 MiB.'); return; }
  const raw = await readBounded(message.raw);
  if (!raw) { message.setReject('Message too large. Send at most 2 MiB.'); return; }
  // Hash the exact message and envelope recipient; Message-ID alone is sender-controlled.
  const recipientBytes = new TextEncoder().encode(recipient + '\0');
  const hashInput = new Uint8Array(recipientBytes.length + raw.length);
  hashInput.set(recipientBytes); hashInput.set(raw, recipientBytes.length);
  const digest = await crypto.subtle.digest('SHA-256', hashInput);
  const dedupe = [...new Uint8Array(digest)].map(n => n.toString(16).padStart(2,'0')).join('');
  const parsed = await PostalMime.parse(raw);
  const body = String(parsed.text || plainHtml(parsed.html) || '(This message has no readable text.)').replace(/\u0000/gu, '');
  // Await the durable write. A DB failure must fail the event, never silently accept and lose mail.
  await env.DB.prepare(`INSERT INTO platform_staff_inbox_v84_3
    (id,dedupe_key,from_email,from_name,header_from_email,to_email,subject,text_body,received_at,attachment_count,truncated)
    VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(dedupe_key) DO NOTHING`)
    .bind(crypto.randomUUID(), dedupe, clean(message.from,320), clean(parsed.from?.name,160),
      clean(parsed.from?.address,320), recipient, clean(parsed.subject,300) || '(No subject)',
      body.slice(0,MAX_TEXT), Date.now(), parsed.attachments?.length ?? 0, body.length > MAX_TEXT ? 1 : 0).run();
}

function summary(row) {
  return {id:row.id,from:row.from_email,fromName:row.from_name,to:row.to_email,subject:row.subject,
    receivedAt:Number(row.received_at),attachmentCount:Number(row.attachment_count),truncated:Boolean(row.truncated)};
}

export async function recordStaffCenterAccess(env, actor, action, count) {
  await env.DB.prepare(`INSERT INTO platform_staff_access_audit_v84_3
    (id,actor_user_id,action,row_count,created_at) VALUES (?,?,?,?,?)`)
    .bind(crypto.randomUUID(), actor, action, count, Date.now()).run();
}

export function createStaffCenter({ authorize, json, rateLimit, audit = recordStaffCenterAccess }) {
  const respond = (data, status=200) => privateResponse(json(data,status));
  return async function staffCenter(request, env) {
    const auth = await authorize(request,env);
    if ('response' in auth) return privateResponse(auth.response);
    const {user,permissions=[]} = auth;
    if (!['creator','staff'].includes(user.platform_role)) return respond({error:'Founder or platform Staff access required.'},403);
    if (!['view_accounts','view_verified_emails'].every(permission=>permissions.includes(permission)))
      return respond({error:'Account and verified email viewing permissions are required.'},403);
    if (request.headers.get('X-Spaces-Developer-Mode') !== '1') return respond({error:'Enable Developer Mode to open the Support Center.'},403);
    if (request.method !== 'GET') return respond({error:'Method not allowed.'},405);
    await rateLimit(request,env,'staff-center-read-v843',300,3600000,user.id);
    const url = new URL(request.url), route = url.pathname.slice('/v1/staff/center'.length);
    const query = clean(url.searchParams.get('q'),80);
    const q = literal(query);
    if (route === '/accounts') {
      if (query.length < 2) return respond({accounts:[]});
      const {results=[]} = await env.DB.prepare(`SELECT id,public_user_id,username,display_name,email,email_verified,platform_role FROM users
        WHERE username LIKE ? ESCAPE '\\' OR display_name LIKE ? ESCAPE '\\' OR public_user_id LIKE ? ESCAPE '\\'
        OR (email_verified = 1 AND email LIKE ? ESCAPE '\\') ORDER BY username LIMIT 30`).bind(q,q,q,q).all();
      await audit(env,user.id,'member_email_lookup',results.length);
      return respond({accounts:results.map(row=>({id:row.id,publicUserId:row.public_user_id,username:row.username,
        displayName:row.display_name,email:row.email_verified?row.email:null,verified:Boolean(row.email_verified),
        platformRole:row.platform_role==='creator'?'founder':row.platform_role}))});
    }
    if (route === '/sent') {
      const {results=[]}=await env.DB.prepare(`SELECT d.id,d.sender_address,d.recipient_email,d.subject,d.status,d.created_at,
        COALESCE(u.username,'') AS recipient_username,COALESCE(a.username,'') AS staff_username
        FROM platform_email_deliveries_v84 d LEFT JOIN users u ON u.id=d.recipient_user_id LEFT JOIN users a ON a.id=d.actor_user_id
        WHERE d.subject LIKE ? ESCAPE '\\' OR d.recipient_email LIKE ? ESCAPE '\\' OR u.username LIKE ? ESCAPE '\\'
        ORDER BY d.created_at DESC,d.id DESC LIMIT 100`).bind(q,q,q).all();
      await audit(env,user.id,'outbound_delivery_history',results.length);
      return respond({deliveries:results.map(row=>({id:row.id,from:row.sender_address,to:row.recipient_email,subject:row.subject,
        status:row.status,createdAt:Number(row.created_at),recipientUsername:row.recipient_username,staffUsername:row.staff_username}))});
    }
    if (route === '/inbox') {
      let before = Number.MAX_SAFE_INTEGER, beforeId = '\uffff';
      const cursor = url.searchParams.get('cursor');
      if (cursor) {
        const match=cursor.match(/^(\d{1,16}):([0-9a-f-]{36})$/u);
        if (!match || !Number.isSafeInteger(Number(match[1]))) return respond({error:'Invalid inbox cursor.'},400);
        before=Number(match[1]);beforeId=match[2];
      }
      const {results=[]}=await env.DB.prepare(`SELECT id,from_email,from_name,to_email,subject,received_at,attachment_count,truncated
        FROM platform_staff_inbox_v84_3 WHERE (received_at < ? OR (received_at = ? AND id < ?))
        AND (subject LIKE ? ESCAPE '\\' OR from_email LIKE ? ESCAPE '\\' OR from_name LIKE ? ESCAPE '\\')
        ORDER BY received_at DESC,id DESC LIMIT 51`).bind(before,before,beforeId,q,q,q).all();
      const rows=results.slice(0,50),last=rows.at(-1);
      const newest=await env.DB.prepare('SELECT MAX(received_at) AS last_received FROM platform_staff_inbox_v84_3').first();
      await audit(env,user.id,'inbound_email_list',rows.length);
      return respond({messages:rows.map(summary),nextCursor:results.length>50?`${last.received_at}:${last.id}`:null,
        lastReceivedAt:newest?.last_received??null,mailboxes:[...MAILBOXES]});
    }
    const detail = route.match(/^\/inbox\/([0-9a-f-]{36})$/u);
    if (detail) {
      const row=await env.DB.prepare('SELECT * FROM platform_staff_inbox_v84_3 WHERE id=?').bind(detail[1]).first();
      await audit(env,user.id,'inbound_email_read',row?1:0);
      if (!row) return respond({error:'Message not found.'},404);
      const account=await env.DB.prepare('SELECT username,email FROM users WHERE email_verified=1 AND lower(email)=lower(?) LIMIT 1').bind(row.from_email).first();
      return respond({message:{...summary(row),text:row.text_body,headerFrom:row.header_from_email,
        matchedAccount:account?{username:account.username,email:account.email}:null}});
    }
    return respond({error:'Support Center route not found.'},404);
  };
}
