/** Spaces V90 program applications. All authority is checked server-side.
 * Contact emails are limited to authorized reviewers of Partner applications.
 */
export async function handleSpacesProgramsV90(request,env,url,deps){
 const {requireWorkspaceMembership,requireSupportConsole,supportPermissionsForUserV48,fail,json,readJson,enforceRateLimit}=deps;
 const privateJson=(data,status=200)=>{const response=json(data,status);response.headers.set('Cache-Control','private, no-store');return response;};
 const ownerRoute=url.pathname.match(/^\/v1\/workspaces\/([^/]+)\/program-applications$/u);
 const badgesRoute=url.pathname.match(/^\/v1\/workspaces\/([^/]+)\/program-badges$/u);
 const queue=url.pathname==='/v1/support/program-applications';
 const decision=url.pathname.match(/^\/v1\/support\/program-applications\/([^/]+)$/u);
 if(!ownerRoute&&!badgesRoute&&!queue&&!decision)return null;
 // Member-only badge read; badge state never contains email/contact details.
 if(badgesRoute&&request.method==='GET'){
   const spaceId=decodeURIComponent(badgesRoute[1]);
   const member=await requireWorkspaceMembership(request,env,spaceId);if('response' in member)return member.response;
   const badges=await env.DB.prepare('SELECT program,approved_at AS approvedAt FROM space_program_badges_v90 WHERE space_id=?').bind(spaceId).all();
   return privateJson({badges:badges.results||[]});
 }
 if(ownerRoute){
   const spaceId=decodeURIComponent(ownerRoute[1]);
   const member=await requireWorkspaceMembership(request,env,spaceId);if('response' in member)return member.response;
   const space=await env.DB.prepare('SELECT id,name,owner_user_id FROM spaces WHERE id=?').bind(spaceId).first();
   if(!space)return fail('Space not found.',404);
   // Only the Space owner may submit or inspect its applications.
   if(space.owner_user_id!==member.user.id)return fail('Only the Space owner can manage applications.',403);
   if(request.method==='GET'){
     const records=await env.DB.prepare('SELECT id,program,statement,public_link AS publicLink,status,reviewer_note AS reviewerNote,created_at AS createdAt,reviewed_at AS reviewedAt FROM space_program_applications_v90 WHERE space_id=? ORDER BY created_at DESC LIMIT 30').bind(spaceId).all();
     const badges=await env.DB.prepare('SELECT program,approved_at AS approvedAt FROM space_program_badges_v90 WHERE space_id=?').bind(spaceId).all();
     return privateJson({applications:records.results||[],badges:badges.results||[]});
   }
   if(request.method==='POST'){
     await enforceRateLimit(request,env,'program-apply-v90',4,3600000,member.user.id);
     const body=await readJson(request);
     const program=String(body.program||'');
     if(!['verified','partner'].includes(program))return fail('Invalid application type.',400);
     const statement=String(body.statement||'').trim();const publicLink=String(body.publicLink||'').trim();
     if(statement.length<20||statement.length>2500)return fail('Explain your application in 20–2500 characters.',400);
     if(publicLink.length>350|| (publicLink&&!/^https:\/\/[^\s]+$/i.test(publicLink)))return fail('Links must be HTTPS URLs.',400);
     if(body.contactConsent!==true)return fail('Contact disclosure acknowledgement is required.',400);
     const existing=await env.DB.prepare("SELECT id FROM space_program_applications_v90 WHERE space_id=? AND program=? AND status='pending'").bind(spaceId,program).first();
     if(existing)return fail('An application for this program is already pending.',409);
     const now=Date.now(), id=crypto.randomUUID();
     try{
       await env.DB.prepare('INSERT INTO space_program_applications_v90(id,space_id,owner_user_id,program,statement,public_link,contact_consent,status,created_at,updated_at) VALUES(?,?,?,?,?,?,1,\'pending\',?,?)').bind(id,spaceId,member.user.id,program,statement,publicLink,now,now).run();
     }catch(e){if(String(e).includes('UNIQUE'))return fail('An application is already pending.',409);throw e}
     return privateJson({ok:true,id,status:'pending'},201);
   }
   return fail('Unsupported method.',405);
 }
 // Platform Support role deliberately cannot access program reviews or owner email.
 const support=await requireSupportConsole(request,env);if('response' in support)return support.response;
 if(!['creator','staff'].includes(support.user.platform_role))return fail('Founder or Staff required.',403);
 const perms=await supportPermissionsForUserV48(env,support.user);
 if(!perms.includes('view_reports'))return fail('Review permission required.',403);
 if(queue&&request.method==='GET'){
   const status=url.searchParams.get('status')||'pending';
   if(!['pending','approved','rejected','withdrawn','all'].includes(status))return fail('Invalid status.',400);
   const rows=await env.DB.prepare(`SELECT a.id,a.space_id AS spaceId,s.name AS spaceName,a.owner_user_id AS ownerId,
       u.display_name AS ownerName,u.username AS ownerUsername,a.program,a.statement,a.public_link AS publicLink,
       a.status,a.reviewer_note AS reviewerNote,a.created_at AS createdAt,a.reviewed_at AS reviewedAt,
       CASE WHEN a.program='partner' AND a.contact_consent=1 AND u.email_verified=1 AND ?=1 THEN u.email ELSE NULL END AS contactEmail
       FROM space_program_applications_v90 a JOIN spaces s ON s.id=a.space_id
       JOIN users u ON u.id=a.owner_user_id
       WHERE (?='all' OR a.status=?) ORDER BY CASE a.status WHEN 'pending' THEN 0 ELSE 1 END,a.created_at DESC LIMIT 150`)
       .bind(perms.includes('view_verified_emails')?1:0,status,status).all();
   return privateJson({applications:rows.results||[],canViewVerifiedEmails:perms.includes('view_verified_emails')});
 }
 if(decision&&request.method==='PATCH'){
   if(!perms.includes('manage_reports'))return fail('Approval permission required.',403);
   await enforceRateLimit(request,env,'program-review-v90',90,3600000,support.user.id);
   const id=decodeURIComponent(decision[1]);
   const body=await readJson(request);const status=String(body.status||'');const note=String(body.note||'').trim();
   if(!['approved','rejected'].includes(status))return fail('Invalid decision.',400);
   if(note.length>750)return fail('Review note must be at most 750 characters.',400);
   const row=await env.DB.prepare("SELECT a.*,s.owner_user_id AS current_owner FROM space_program_applications_v90 a JOIN spaces s ON s.id=a.space_id WHERE a.id=?").bind(id).first();
   if(!row)return fail('Application not found.',404);
   if(row.status!=='pending')return fail('Application is no longer pending.',409);
   if(row.current_owner!==row.owner_user_id)return fail('Space ownership changed; request a new application.',409);
   if(support.user.id===row.owner_user_id&&support.user.platform_role!=='creator')return fail('Staff cannot review their own Space application.',403);
   const now=Date.now();
   // compare-and-swap update prevents accepting the same review twice.
   const update=env.DB.prepare("UPDATE space_program_applications_v90 SET status=?,reviewer_user_id=?,reviewer_note=?,reviewed_at=?,updated_at=? WHERE id=? AND status='pending'").bind(status,support.user.id,note,now,now,id);
   const badge=status==='approved'
      ?env.DB.prepare("INSERT INTO space_program_badges_v90(space_id,program,approved_by,approved_at) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM space_program_applications_v90 WHERE id=? AND status='approved' AND reviewer_user_id=?) ON CONFLICT(space_id,program) DO UPDATE SET approved_by=excluded.approved_by,approved_at=excluded.approved_at").bind(row.space_id,row.program,support.user.id,now,id,support.user.id)
      :env.DB.prepare('SELECT 1'); // A rejected reapplication must not remove an existing approved badge.
   const audit=env.DB.prepare('INSERT INTO support_audit_v77(id,actor_id,actor_role,action,target_type,target_id,reason_category,note,before_json,after_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)').bind(crypto.randomUUID(),support.user.id,support.user.platform_role,'space.program.review','space',row.space_id,row.program,note,JSON.stringify({status:'pending',applicationId:id}),JSON.stringify({status,applicationId:id,program:row.program}),now);
   await env.DB.batch([update,badge,audit]);
   return privateJson({ok:true,id,status});
 }
 return fail('Unsupported method.',405);
}
