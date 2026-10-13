/** V89: Authenticated Space-wide Notes folders, scoped to an existing Notes channel.
 * No client-supplied user IDs, no unauthenticated reads. */
export async function routeNotesFoldersV89(request, env, workspaceId, id, deps) {
  const { requireWorkspaceMembership, fail, json, readJson, channelPermissionRows,
    channelPermissionAllowed, roleMeetsPermission, normalizeChannelPermission, accessHas, enforceRateLimit } = deps;
  const access = await requireWorkspaceMembership(request, env, workspaceId);
  if ('response' in access) return access.response;
  if(request.method!=='GET') await enforceRateLimit(request,env,'note-folder-write',30,60_000,`${workspaceId}:${access.user.id}`);
  const channel = async channelId => env.DB.prepare(
    `SELECT id,kind,note_min_role FROM channels WHERE id=? AND space_id=? LIMIT 1`
  ).bind(channelId,workspaceId).first();
  async function permissions(channelId, action) {
    const row = await channel(channelId);
    if (!row || !['notes','mixed'].includes(row.kind)) return { ok:false, response:fail('Note channel not found.',404) };
    const rows=await channelPermissionRows(env, workspaceId, channelId);
    if (!channelPermissionAllowed(access, rows, 'view_channel', true)) return { ok:false,response:fail('Channel access denied.',403) };
    if (action && !channelPermissionAllowed(access,rows,action,
      row.note_min_role!=='disabled'&&(roleMeetsPermission(access.role,normalizeChannelPermission(row.note_min_role,'contributor'))||accessHas(access,'edit_notes')))) return {ok:false,response:fail('Notes permission required.',403)};
    return {ok:true,row};
  }
  const url = new URL(request.url);
  if(request.method==='GET' && !id){
    const channelId=url.searchParams.get('channelId')||'';
    const gate=await permissions(channelId);if(!gate.ok)return gate.response;
    const folders=await env.DB.prepare(`SELECT id,name,sort_order AS sortOrder,created_by AS createdBy FROM notes_folders_v89 WHERE space_id=? AND channel_id=? ORDER BY sort_order,name`).bind(workspaceId,channelId).all();
    const items=await env.DB.prepare(`SELECT a.note_id AS noteId,a.folder_id AS folderId FROM note_folder_links_v89 a JOIN notes n ON n.id=a.note_id AND n.space_id=a.space_id WHERE a.space_id=? AND n.channel_id=?`).bind(workspaceId,channelId).all();
    return json({folders:folders.results||[],assignments:items.results||[]});
  }
  if(request.method==='POST' && !id){
    const data=await readJson(request);const channelId=String(data.channelId||'');
    const gate=await permissions(channelId,'create_notes');if(!gate.ok)return gate.response;
    const name=String(data.name||'').trim();if(name.length<1||name.length>64)return fail('Folder name must be 1–64 characters.');
    const count=await env.DB.prepare('SELECT COUNT(*) AS n FROM notes_folders_v89 WHERE space_id=? AND channel_id=?').bind(workspaceId,channelId).first();
    if(Number(count?.n||0)>=60)return fail('This channel has reached the 60-folder limit.');
    const row={id:crypto.randomUUID(),name,channelId,createdBy:access.user.id};
    await env.DB.prepare('INSERT INTO notes_folders_v89(id,space_id,channel_id,name,sort_order,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)').bind(row.id,workspaceId,channelId,name,Number(count?.n||0),access.user.id,Date.now(),Date.now()).run();
    return json(row,201);
  }
  if(request.method==='PUT'&&id==='assign'){
    const data=await readJson(request);
    const channelId=String(data.channelId||'');const noteId=String(data.noteId||'');const folderId=data.folderId==null?null:String(data.folderId);
    const gate=await permissions(channelId,'edit_notes');if(!gate.ok)return gate.response;
    const note=await env.DB.prepare('SELECT id FROM notes WHERE id=? AND channel_id=? AND space_id=? LIMIT 1').bind(noteId,channelId,workspaceId).first();
    if(!note)return fail('Note is not in this channel.',404);
    if(folderId){const f=await env.DB.prepare('SELECT id FROM notes_folders_v89 WHERE id=? AND channel_id=? AND space_id=? LIMIT 1').bind(folderId,channelId,workspaceId).first();if(!f)return fail('Folder is not in this channel.',404)}
    if(folderId){await env.DB.prepare(`INSERT INTO note_folder_links_v89(space_id,note_id,folder_id,updated_at) VALUES(?,?,?,?) ON CONFLICT(space_id,note_id) DO UPDATE SET folder_id=excluded.folder_id,updated_at=excluded.updated_at`).bind(workspaceId,noteId,folderId,Date.now()).run()}
    else await env.DB.prepare('DELETE FROM note_folder_links_v89 WHERE space_id=? AND note_id=?').bind(workspaceId,noteId).run();
    return json({ok:true});
  }
  if(id && id!=='assign' && ['PATCH','DELETE'].includes(request.method)){
    const f=await env.DB.prepare('SELECT * FROM notes_folders_v89 WHERE id=? AND space_id=? LIMIT 1').bind(id,workspaceId).first();
    if(!f)return fail('Folder not found.',404);
    const gate=await permissions(f.channel_id, 'edit_notes');if(!gate.ok)return gate.response;
    if(request.method==='PATCH'){
      const data=await readJson(request);const name=String(data.name||'').trim();if(!name||name.length>64)return fail('Invalid folder name.');
      await env.DB.prepare('UPDATE notes_folders_v89 SET name=?,updated_at=? WHERE id=? AND space_id=?').bind(name,Date.now(),id,workspaceId).run();
      return json({ok:true,name});
    }
    await env.DB.batch([env.DB.prepare('DELETE FROM note_folder_links_v89 WHERE space_id=? AND folder_id=?').bind(workspaceId,id),env.DB.prepare('DELETE FROM notes_folders_v89 WHERE space_id=? AND id=?').bind(workspaceId,id)]);
    return json({ok:true});
  }
  return fail('Unsupported folder operation.',405);
}
