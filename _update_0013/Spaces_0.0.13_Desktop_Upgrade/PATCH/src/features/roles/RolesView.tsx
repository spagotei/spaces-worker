import { useEffect, useMemo, useState } from 'react'
import { Icon } from '../../components/Icon'
import { useSpaces } from '../../state/SpacesContext'
import { hasWorkspacePermission } from '../../utils/permissions'
import type { WorkspaceCustomPermission, WorkspaceCustomRole } from '../../types/spaces'

const permissionLabels: Record<WorkspaceCustomPermission, [string,string]> = {
  send_messages: ['Send messages','Write in channels that allow this role.'], attach_files: ['Attach files','Upload supported files in chat.'],
  mention_everyone: ['Mention @everyone / @here','Send high-priority pings to the whole Space or active members.'],
  edit_notes: ['Create & edit notes','Create, import and update shared notes.'], delete_notes: ['Delete notes','Remove shared notes.'],
  create_channels: ['Create channels','Add new chat and note channels.'], manage_channels: ['Manage channels','Change channel access and structure.'],
  create_invites: ['Create invites','Invite new members to this Space.'], manage_members: ['Manage members','Remove members and manage base access.'],
  manage_roles: ['Manage roles','Create roles and assign permissions below this role.'], manage_space: ['Manage Space','Edit Space identity and shared settings.'],
  manage_emojis: ['Manage emoji','Add and remove custom emoji.'], moderate_messages: ['Moderate messages','Remove messages and review reports.'],
  moderate_comments: ['Moderate comments','Remove comments from shared notes.'], view_audit_log: ['View audit log','See staff and moderation activity.'],
}
const groups: { title: string; description: string; permissions: WorkspaceCustomPermission[] }[] = [
  { title: 'Messaging', description: 'Conversation and attachment controls.', permissions: ['send_messages','attach_files','mention_everyone'] },
  { title: 'Knowledge', description: 'Shared notes and documentation.', permissions: ['edit_notes','delete_notes'] },
  { title: 'Channels', description: 'Structure and channel-level access.', permissions: ['create_channels','manage_channels'] },
  { title: 'Community', description: 'Invites, members, roles and customization.', permissions: ['create_invites','manage_members','manage_roles','manage_emojis'] },
  { title: 'Moderation', description: 'Sensitive staff capabilities.', permissions: ['moderate_messages','moderate_comments','view_audit_log'] },
  { title: 'Administration', description: 'Highest Space-level control.', permissions: ['manage_space'] },
]
const allPermissions = Object.keys(permissionLabels) as WorkspaceCustomPermission[]
const blank = { name: '', color: '#8b6ca8', permissions: [] as WorkspaceCustomPermission[], hoist: false, mentionable: false }

type ProtectedRole = 'owner' | 'admin' | 'member'

export function RolesView() {
  const { data, profile, createRole, updateRole, deleteRole, pushToast } = useSpaces()
  const roles = useMemo(() => [...(data?.roles ?? [])].sort((a,b) => b.position-a.position), [data?.roles])
  const currentMember = data?.members.find(member => member.profileId === profile?.id)
  const canManage = hasWorkspacePermission(data, profile?.id, 'manage_roles')
  const [selectedId,setSelectedId]=useState('')
  const [protectedRole,setProtectedRole]=useState<ProtectedRole | null>('owner')
  const [creating,setCreating]=useState(false)
  const selected=roles.find(role=>role.id===selectedId) ?? null
  const [draft,setDraft]=useState(blank)
  const [saving,setSaving]=useState(false)

  useEffect(()=>{ if(selected){ setProtectedRole(null); setCreating(false); setDraft({name:selected.name,color:selected.color,permissions:[...selected.permissions],hoist:selected.hoist,mentionable:selected.mentionable}) } },[selected])
  function begin(input=blank){ setSelectedId(''); setProtectedRole(null); setCreating(true); setDraft({...input,permissions:[...input.permissions]}) }
  function selectProtected(role: ProtectedRole){ setSelectedId(''); setCreating(false); setProtectedRole(role) }
  async function save(){ if(!draft.name.trim()||!canManage)return; setSaving(true); try{ if(selected) await updateRole(selected.id,draft); else await createRole(draft); setCreating(false) } catch(error){ pushToast(error instanceof Error ? error.message : 'Could not save role.', 'danger') } finally{setSaving(false)} }
  async function remove(role:WorkspaceCustomRole){ if(!window.confirm(`Delete role “${role.name}”?`))return; try { await deleteRole(role.id); setSelectedId(''); setProtectedRole('owner'); setCreating(false) } catch(error){ pushToast(error instanceof Error ? error.message : 'Could not delete role.', 'danger') } }
  function toggle(permission:WorkspaceCustomPermission,checked:boolean){ setDraft(current=>({...current,permissions:checked?[...current.permissions,permission]:current.permissions.filter(item=>item!==permission)})) }
  const preset=(name:string,color:string,permissions:WorkspaceCustomPermission[])=>begin({name,color,permissions,hoist:true,mentionable:true})
  const protectedPermissions = protectedRole === 'member' ? ['send_messages','attach_files','edit_notes'] as WorkspaceCustomPermission[] : allPermissions
  const protectedLabel = protectedRole === 'owner' ? 'Owner' : protectedRole === 'admin' ? 'Administrator' : 'Member'
  const protectedDescription = protectedRole === 'owner'
    ? 'The Owner sits above every role. It always has every permission and can never be edited, removed or outranked.'
    : protectedRole === 'admin'
      ? 'Legacy administrator access. Administrators have broad Space management access, but they remain below the Owner.'
      : 'Default member access. Channel-specific rules can further limit what members can do.'

  return <div className="roles-view roles-view-v2 roles-view-v9 page-enter">
    <aside className="roles-list-panel">
      <header><div><span className="eyebrow">ROLE HIERARCHY</span><h2>Roles</h2><p>Higher roles manage only the roles beneath them.</p></div></header>
      {canManage && <button className="create-role-button" onClick={()=>begin()}><Icon name="plus" size={15}/><span><strong>Create role</strong><small>Build a new permission set</small></span></button>}
      <div className="hierarchy-stack">
        <button className={`protected-role-row owner ${protectedRole==='owner'?'active':''}`} onClick={()=>selectProtected('owner')}><span className="hierarchy-grip">⋮⋮</span><i className="role-swatch owner"/><span><strong>Owner</strong><small>Highest · protected · all permissions</small></span><Icon name="lock" size={13}/></button>
        <button className={`protected-role-row admin ${protectedRole==='admin'?'active':''}`} onClick={()=>selectProtected('admin')}><span className="hierarchy-grip">⋮⋮</span><i className="role-swatch admin"/><span><strong>Administrator</strong><small>Base role · below Owner</small></span><Icon name="shield" size={13}/></button>
        {roles.map((role,index)=><button className={`custom-hierarchy-row ${selected?.id===role.id?'active':''}`} key={role.id} onClick={()=>setSelectedId(role.id)}><span className="hierarchy-rank">{index+1}</span><span className="role-swatch" style={{background:role.color}}/><span><strong>{role.name}</strong><small>{role.permissions.length} permissions · position {role.position}</small></span><Icon name="chevron" size={14}/></button>)}
        <button className={`protected-role-row member ${protectedRole==='member'?'active':''}`} onClick={()=>selectProtected('member')}><span className="hierarchy-grip">⋮⋮</span><i className="role-swatch member"/><span><strong>Member</strong><small>Default access</small></span></button>
      </div>
    </aside>

    <section className="role-editor-panel">
      {protectedRole ? <>
        <div className="content-heading compact-heading"><div><span className="eyebrow">PROTECTED ROLE</span><h1>{protectedLabel}</h1><p>{protectedDescription}</p></div><span className="protected-role-badge"><Icon name="lock" size={13}/>{protectedRole === 'owner' ? 'Immutable' : 'Base role'}</span></div>
        {protectedRole === 'owner' && <div className="owner-role-callout"><Icon name="shield" size={22}/><div><strong>Owner always wins the hierarchy</strong><span>No member, Co-Owner, Staff or custom role can change the Owner. Server-side hierarchy checks protect role assignment and management.</span></div></div>}
        <div className="permission-matrix protected-permission-matrix">{groups.map(group=><section key={group.title}><header><div><strong>{group.title}</strong><span>{group.description}</span></div><small>{group.permissions.filter(permission=>protectedPermissions.includes(permission)).length}/{group.permissions.length}</small></header><div>{group.permissions.map(permission=>{const [label,desc]=permissionLabels[permission];const checked=protectedPermissions.includes(permission);return <div className={`permission-line ${checked?'enabled':''}`} key={permission}><div><strong>{label}</strong><span>{desc}</span></div><span className={`permission-toggle ${checked?'on':''} locked`}><i/></span></div>})}</div></section>)}</div>
      </> : <>
        <div className="content-heading compact-heading"><div><span className="eyebrow">{selected?'EDIT ROLE':creating?'NEW ROLE':'ROLE DESIGNER'}</span><h1>{selected?.name ?? (creating?'Create role':'Permissions')}</h1><p>{selected||creating?'Configure identity, visibility and exact capabilities.':'Select a role or create one to begin.'}</p></div>{selected&&canManage&&<button className="ghost-danger" onClick={()=>void remove(selected)}><Icon name="trash" size={15}/>Delete</button>}</div>
        {!selected&&!creating&&canManage&&<div className="role-onboarding"><Icon name="roles" size={28}/><h3>Build your Space hierarchy</h3><p>Owners are permanently at the top. Custom roles are stackable and can only manage roles below their own highest position.</p><div className="role-preset-cards"><button onClick={()=>preset('Co-Owner','#b49ad0',allPermissions)}><strong>Co-Owner</strong><span>Full operational access below Owner</span></button><button onClick={()=>preset('Staff','#7f9dbb',['send_messages','attach_files','mention_everyone','edit_notes','delete_notes','create_invites','manage_members','moderate_messages','moderate_comments','view_audit_log'])}><strong>Staff</strong><span>Community + moderation</span></button><button onClick={()=>preset('Moderator','#83a98f',['send_messages','attach_files','moderate_messages','moderate_comments','view_audit_log'])}><strong>Moderator</strong><span>Moderation focused</span></button><button onClick={()=>begin()}><strong>Custom</strong><span>Start with no permissions</span></button></div></div>}
        {(selected||creating)&&<>
          <section className="role-identity-card"><div className="role-preview-orb" style={{background:draft.color}}/><label><span>ROLE NAME</span><input className="text-input" disabled={!canManage} value={draft.name} maxLength={32} onChange={e=>setDraft(c=>({...c,name:e.target.value}))}/></label><label className="role-color-field"><span>COLOR</span><input type="color" disabled={!canManage} value={draft.color} onChange={e=>setDraft(c=>({...c,color:e.target.value}))}/><code>{draft.color}</code></label></section>
          <div className="role-toggle-row"><label><input type="checkbox" disabled={!canManage} checked={draft.hoist} onChange={e=>setDraft(c=>({...c,hoist:e.target.checked}))}/><span><strong>Display members separately</strong><small>Create a dedicated section in the member list.</small></span></label><label><input type="checkbox" disabled={!canManage} checked={draft.mentionable} onChange={e=>setDraft(c=>({...c,mentionable:e.target.checked}))}/><span><strong>Allow role mentions</strong><small>Members can target this role with @mentions.</small></span></label></div>
          <div className="permission-matrix">{groups.map(group=><section key={group.title}><header><div><strong>{group.title}</strong><span>{group.description}</span></div><small>{group.permissions.filter(p=>draft.permissions.includes(p)).length}/{group.permissions.length}</small></header><div>{group.permissions.map(permission=>{const [label,desc]=permissionLabels[permission];const checked=draft.permissions.includes(permission);return <label className={`permission-line ${checked?'enabled':''}`} key={permission}><div><strong>{label}</strong><span>{desc}</span></div><button type="button" className={`permission-toggle ${checked?'on':''}`} disabled={!canManage} onClick={()=>toggle(permission,!checked)} aria-pressed={checked}><i/></button></label>})}</div></section>)}</div>
          {canManage&&<div className="sticky-save"><span>{draft.permissions.length} permission{draft.permissions.length===1?'':'s'} enabled · {currentMember?.role === 'owner' ? 'Owner access' : 'Hierarchy rules apply'}</span><button className="primary-button" disabled={saving||!draft.name.trim()} onClick={()=>void save()}>{saving?'Saving…':selected?'Save role':'Create role'}</button></div>}
        </>}
      </>}
    </section>
  </div>
}
