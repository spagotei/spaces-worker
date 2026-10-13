/* Spaces V85 — server-side call history, not user-generated chat messages.
   All exported reads require the calling Worker's existing auth and DM membership checks. */
const RINGING = 'ringing';
const MAX_MS = 2 * 60 * 60 * 1000;

export async function finishDmCallV85(env, row, reason, at = Date.now()) {
  if (!row || row.status === 'ended') return;
  const answeredAt = Number(row.connected_at || 0);
  const completed = row.status === 'active' && answeredAt > 0;
  // A decline is not a missed call: the callee explicitly declined it.
  const kind = completed ? 'ended' : reason === 'decline' ? 'declined' : 'missed';
  const duration = completed ? Math.min(Math.floor(Math.max(0, at - answeredAt) / 1000), MAX_MS / 1000) : 0;
  await env.DB.prepare(`INSERT INTO voice_dm_events_v85
     (call_id, conversation_id, caller_user_id, callee_user_id, kind, duration_seconds, created_at)
     VALUES (?,?,?,?,?,?,?) ON CONFLICT(call_id) DO NOTHING`)
    .bind(row.id, row.conversation_id, row.caller_user_id, row.callee_user_id, kind, duration, at).run();
}

export async function finalizeExpiredDmCallsV85(env, now = Date.now()) {
  const {results=[]} = await env.DB.prepare(`SELECT * FROM voice_dm_calls_v81
     WHERE status IN ('ringing','active') AND expires_at <= ? ORDER BY expires_at ASC LIMIT 100`).bind(now).all();
  for (const row of results) {
    await finishDmCallV85(env, row, 'timeout', Number(row.expires_at));
    await env.DB.prepare(`UPDATE voice_dm_calls_v81 SET status='ended',updated_at=? WHERE id=? AND status!='ended'`)
      .bind(now, row.id).run();
  }
}

export async function getDmCallEventsV85(request, env, {requireUser, directConversationForUser, json, fail}) {
  if (request.method !== 'GET') return fail('Method not allowed.',405);
  const auth = await requireUser(request, env);
  if ('response' in auth) return auth.response;
  const conversationId = new URL(request.url).searchParams.get('conversationId') || '';
  if (conversationId.length > 128 || !conversationId) return fail('Invalid conversation.',400);
  const conversation = await directConversationForUser(env, conversationId, auth.user.id);
  if (!conversation || conversation.status !== 'accepted') return fail('Direct conversation not found.',404);
  await finalizeExpiredDmCallsV85(env);
  const {results=[]} = await env.DB.prepare(`SELECT call_id,kind,duration_seconds,created_at,caller_user_id,callee_user_id
    FROM voice_dm_events_v85 WHERE conversation_id=? AND (caller_user_id=? OR callee_user_id=?)
    ORDER BY created_at DESC LIMIT 100`).bind(conversationId,auth.user.id,auth.user.id).all();
  const events = results.map(row => ({callId: row.call_id, kind: row.kind,
    durationSeconds:Number(row.duration_seconds)||0, createdAt:Number(row.created_at),
    direction:row.caller_user_id===auth.user.id?'outgoing':'incoming'}));
  return new Response(JSON.stringify({events}),{status:200,headers:{
    'Content-Type':'application/json; charset=utf-8','Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'}});
}

export async function missedDmNotificationsV85(env, userId, since, cursors, globalRead, mutedKeys, blocked) {
  await finalizeExpiredDmCallsV85(env);
  const {results=[]}=await env.DB.prepare(`SELECT e.call_id,e.conversation_id,e.caller_user_id,e.created_at,
    COALESCE(u.display_name,'Friend') AS caller_name
    FROM voice_dm_events_v85 e JOIN users u ON u.id=e.caller_user_id
    WHERE e.callee_user_id=? AND e.kind='missed' AND e.created_at>?
    ORDER BY e.created_at DESC LIMIT 80`).bind(userId,since).all();
  return results.filter(row => Number(row.created_at)>Math.max(globalRead,Number(cursors.get(`dm:${row.conversation_id}`)||0))
    && !mutedKeys.has(`dm:${row.conversation_id}`) && !blocked.has(String(row.caller_user_id)))
    .map(row => ({id:`missed-call-${row.call_id}`,workspaceId:'__direct__',workspaceName:'Direct Messages',
      channelId:row.conversation_id,channelName:'Direct Message',authorName:row.caller_name,
      preview:`Missed call from ${row.caller_name}`,createdAt:Number(row.created_at),
      kind:'direct',mentionLabel:'Missed call',conversationId:row.conversation_id}));
}
