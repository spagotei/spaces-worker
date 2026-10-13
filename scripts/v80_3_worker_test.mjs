// SPACES_V80_3_TESTS: no production DB or external email delivery.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const root = resolve(process.argv[2] || process.cwd());
const sqlite = new DatabaseSync(':memory:');
sqlite.exec('PRAGMA foreign_keys=ON');
for (const filename of readdirSync(join(root,'migrations')).filter(n => /^\d{4}.*\.sql$/u.test(n)).sort()) {
  sqlite.exec(readFileSync(join(root,'migrations',filename),'utf8'));
}
class Prepared {
  constructor(sql,args=[]){this.sql=sql;this.args=args;}
  bind(...args){return new Prepared(this.sql,args);}
  first(){return sqlite.prepare(this.sql).get(...this.args) ?? null;}
  all(){return {results:sqlite.prepare(this.sql).all(...this.args)};}
  run(){const result=sqlite.prepare(this.sql).run(...this.args);return {success:true,meta:{changes:Number(result.changes ?? 0)}};}
}
const DB = {
  prepare(sql){return new Prepared(sql);},
  async batch(statements){
    sqlite.exec('BEGIN');
    try {const result=statements.map(s=>s.run());sqlite.exec('COMMIT');return result;}
    catch(error){sqlite.exec('ROLLBACK');throw error;}
  },
};
const now=Date.now();
const users = [
  ['founder','founder','creator','founder@yourspaces.net','00002'],
  ['staff','staff','staff','staff@yourspaces.net','00020'],
  ['support','support','support','support@yourspaces.net','00021'],
  ['member','member',null,'member@yourspaces.net','00022'],
  ['other','other',null,'other@yourspaces.net','00023'],
];
for (const [id,username,role,email,publicId] of users) {
  sqlite.prepare(`INSERT INTO users (id,username,display_name,password_salt,password_hash,platform_role,created_at,updated_at,email,email_verified,spaces_access,public_user_id) VALUES (?,?,?,'salt','hash',?,?,?,?,1,1,?)`)
    .run(id,username,username,role,now,now,email,publicId);
  const hash=createHash('sha256').update(`token-${id}`).digest('base64');
  sqlite.prepare(`INSERT INTO sessions (id,user_id,token_hash,created_at,expires_at,last_seen_at) VALUES (?,?,?,?,?,?)`).run(`session-${id}`,id,hash,now,now+3600000,now);
}
sqlite.prepare(`INSERT INTO spaces (id,name,code,join_password_salt,join_password_hash,owner_user_id,created_at,updated_at) VALUES ('space-a','Partner Test Space','partner-test','salt','hash','member',?,?)`).run(now,now);
sqlite.prepare(`INSERT INTO support_cases_v77 (id,case_number,case_type,reporter_id,target_space_id,subject,status,created_at,updated_at,last_activity_at) VALUES ('case-a','SP-CASE-A','request','member','space-a','Need help','waiting',?,?,?)`).run(now,now,now);
sqlite.prepare(`INSERT INTO support_tickets (id,ticket_number,user_id,topic,status,created_at,updated_at,last_activity_at) VALUES ('ticket-a','TICKET-A','member','Test','waiting',?,?,?)`).run(now,now,now);
const deliveries=[];
const env={DB,SPACES_EMAIL_FROM:'security@yourspaces.net',SPACES_EMAIL_REPLY_TO:'support@yourspaces.net',ALLOWED_ORIGINS:'https://yourspaces.net',EMAIL:{async send(message){deliveries.push(message);return {messageId:`mock-${deliveries.length}`};}}};
const worker=(await import(pathToFileURL(join(root,'src/worker.js')).href)).default;
let passes=0;
async function api(method,path,actor,body){
  const headers={'Origin':'https://yourspaces.net'};
  if(actor) headers.Authorization=`Bearer token-${actor}`;
  if(body!==undefined) headers['Content-Type']='application/json';
  const response=await worker.fetch(new Request(`https://spaces.spagotei.workers.dev${path}`,{method,headers,body:body===undefined?undefined:JSON.stringify(body)}),env);
  const text=await response.text();let value={};try{value=JSON.parse(text)}catch{}
  return {status:response.status,body:value};
}
async function expect(label,method,path,actor,body,status,check){
  const result=await api(method,path,actor,body);
  assert.equal(result.status,status,`${label}: ${JSON.stringify(result.body)}`);
  if(check)check(result.body);
  passes++;console.log(`PASS ${label} (${status})`);
  return result.body;
}
await expect('anonymous cannot approve','POST','/v1/support/partners',null,{spaceId:'space-a',action:'approve'},401);
await expect('member cannot approve','POST','/v1/support/partners','member',{spaceId:'space-a',action:'approve'},403);
await expect('support cannot approve','POST','/v1/support/partners','support',{spaceId:'space-a',action:'approve'},403);
await expect('member applies','POST','/v1/partners/applications','member',{spaceId:'space-a',message:'We run a friendly community with active moderation.'},201);
await expect('owner sees application','GET','/v1/partners/applications','member',undefined,200,v=>assert.equal(v.applications[0].status,'pending'));
await expect('staff sees pending','GET','/v1/support/partners?status=pending','staff',undefined,200,v=>assert.equal(v.applications.length,1));
await expect('staff approves','POST','/v1/support/partners','staff',{spaceId:'space-a',ownerId:'member',action:'approve',note:'Reviewed community'},200,v=>assert.equal(v.approved,true));
await expect('public trust reflects approval','GET','/v1/spaces/trust',null,undefined,200,v=>assert.equal(v.spaces['space-a'].classification,'partner'));
await expect('duplicate application blocked','POST','/v1/partners/applications','member',{spaceId:'space-a',message:'We run a friendly community with active moderation.'},409);
await expect('member cannot email','POST','/v1/support/email','member',{templateId:'ticket-reply',ticketId:'case-a'},403);
await expect('support cannot send security alert','POST','/v1/support/email','support',{templateId:'security-alert',userId:'member'},403);
await expect('support capabilities','GET','/v1/support/email/capabilities','support',undefined,200,v=>assert.equal(v.canSend,true));
await expect('support cannot email arbitrary member','POST','/v1/support/email','support',{templateId:'ticket-reply',userId:'member',variables:{'ticket.reply':'Hello there'}},400);
await expect('unapproved template blocked','POST','/v1/support/email','staff',{templateId:'arbitrary',userId:'member'},400);
await expect('closed-ticket email blocked while waiting','POST','/v1/support/email','staff',{templateId:'ticket-closed',ticketId:'case-a'},409);
await expect('ticket and user mismatch blocked','POST','/v1/support/email','staff',{templateId:'ticket-reply',ticketId:'case-a',userId:'other',variables:{'ticket.reply':'Hello'}},403);
await expect('support sends ticket reply','POST','/v1/support/email','support',{templateId:'ticket-reply',ticketId:'case-a',variables:{'ticket.reply':'We reviewed your request.'}},200,v=>assert.equal(v.sent,true));
assert.equal(deliveries.length,1);
assert.equal(deliveries[0].to.email,'member@yourspaces.net');
assert.equal(deliveries[0].from.email,'security@yourspaces.net');
await expect('duplicate email blocked','POST','/v1/support/email','support',{templateId:'ticket-reply',ticketId:'case-a',variables:{'ticket.reply':'We reviewed your request.'}},409);
await expect('external image blocked','POST','/v1/support/email','founder',{templateId:'partner-approved',userId:'member',variables:{'space.name':'Partner Test Space'},image:{heroUrl:'https://evil.example/track.png'}},400);
await expect('partner approval email','POST','/v1/support/email','staff',{templateId:'partner-approved',userId:'member',variables:{'space.name':'Partner Test Space'}},200,v=>assert.equal(v.sent,true));
assert.equal(deliveries.length,2);
await expect('member archives own case','PATCH','/v1/support/v80/cases/case-a/archive','member',{archived:true},200,v=>assert.equal(v.archived,true));
await expect('other member cannot archive','PATCH','/v1/support/v80/cases/case-a/archive','other',{archived:true},404);
await expect('member archive list','GET','/v1/support/v80/my-archives','member',undefined,200,v=>assert.equal(v.archives.length,1));
await expect('staff archive health','GET','/v1/support/v80/archive-health','staff',undefined,200,v=>assert.equal(v.memberArchiveCount,1));
await expect('member cannot see archive health','GET','/v1/support/v80/archive-health','member',undefined,403);
await expect('member restores own case','PATCH','/v1/support/v80/cases/case-a/archive','member',{archived:false},200);
await expect('member archive list empty','GET','/v1/support/v80/my-archives','member',undefined,200,v=>assert.equal(v.archives.length,0));
await expect('staff revokes Partner','POST','/v1/support/partners','staff',{spaceId:'space-a',action:'revoke',note:'Failed policy review'},200,v=>assert.equal(v.classification,'community'));
await expect('public trust no longer Partner','GET','/v1/spaces/space-a/trust',null,undefined,200,v=>assert.equal(v.classification,'community'));
await expect('audit records decision','GET','/v1/support/partners?status=revoked','founder',undefined,200,v=>assert.equal(v.applications.length,1));

sqlite.prepare(`UPDATE support_tickets SET status='resolved',resolved_at=?,delete_after=? WHERE id='ticket-a'`).run(now,now+86400000);
await expect('member reopens legacy V73 ticket','POST','/v1/support/tickets/TICKET-A/reopen','member',{},200,v=>assert.equal(v.ticket.status,'waiting'));
await expect('staff resolves V77 case','PATCH','/v1/support/v77/cases/case-a','staff',{action:'resolve'},200,v=>assert.equal(v.status,'resolved'));
await expect('staff archives V77 case','PATCH','/v1/support/v77/cases/case-a','staff',{action:'archive'},200,v=>assert.equal(v.status,'archived'));
await expect('member sees archived case','GET','/v1/support/v77/cases/case-a','member',undefined,200,v=>assert.equal(v.status,'archived'));
await expect('member reopens archived case','PATCH','/v1/support/v77/cases/case-a','member',{action:'reopen'},200,v=>assert.equal(v.status,'reviewing'));
await expect('staff cannot archive unresolved case','PATCH','/v1/support/v77/cases/case-a','staff',{action:'archive'},409);
await expect('staff resolves reopened case','PATCH','/v1/support/v77/cases/case-a','staff',{action:'resolve'},200);
await expect('staff archives again','PATCH','/v1/support/v77/cases/case-a','staff',{action:'archive'},200);
await expect('staff cannot permanently delete','DELETE','/v1/support/v77/cases/case-a','staff',undefined,403);
await expect('founder permanently deletes archived case','DELETE','/v1/support/v77/cases/case-a','founder',undefined,204);
await expect('deleted case not found','GET','/v1/support/v77/cases/case-a','member',undefined,404);
console.log(`\n${passes} Worker integration checks passed. Mock email sends: ${deliveries.length}. No external email was sent.`);
