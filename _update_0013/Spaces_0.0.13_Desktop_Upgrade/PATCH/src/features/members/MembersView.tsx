import { useMemo, useState, type CSSProperties } from 'react'
import { Avatar } from '../../components/Avatar'
import { Icon } from '../../components/Icon'
import { GlassSelect } from '../../components/GlassSelect'
import { useSpaces } from '../../state/SpacesContext'
import { usePreferences } from '../../state/PreferencesContext'
import type { WorkspaceRole } from '../../types/spaces'
import { hasWorkspacePermission, platformRoleLabel, workspaceRoleLabel } from '../../utils/permissions'
import { timeAgo } from '../../utils/format'

export function MembersView() {
  const { data, profile, setMemberRoles, changeMemberRole, removeMember, reportUser, pushToast, chooseChannel } = useSpaces()
  const { preferences, effectivePresence } = usePreferences()
  const [selectedId, setSelectedId] = useState('')
  const [savingRoles, setSavingRoles] = useState(false)
  const [savingAccess, setSavingAccess] = useState(false)
  const [reporting, setReporting] = useState(false)
  const members = data?.members ?? []
  const roles = useMemo(() => [...(data?.roles ?? [])].sort((a, b) => b.position - a.position), [data?.roles])
  const selected = members.find(member => member.id === selectedId) ?? members[0] ?? null
  const currentMember = members.find(member => member.profileId === profile?.id) ?? null
  const canManageRoles = hasWorkspacePermission(data, profile?.id, 'manage_roles')
  const canManageMembers = hasWorkspacePermission(data, profile?.id, 'manage_members')

  const selectedRoles = useMemo(() => roles.filter(role => selected?.customRoleIds.includes(role.id)), [roles, selected?.customRoleIds])
  const contributions = useMemo(() => {
    if (!selected || !data) return []
    return data.notes
      .filter(note => note.createdBy === selected.profileId || note.updatedBy === selected.profileId)
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, 6)
      .map(note => ({ ...note, action: note.createdBy === selected.profileId ? 'Created' : 'Edited' }))
  }, [data, selected])

  const canManageSelected = Boolean(
    selected && selected.profileId !== profile?.id && selected.role !== 'owner' && canManageMembers &&
    (currentMember?.role === 'owner' || selected.role !== 'admin'),
  )

  const baseRoleOptions = useMemo<WorkspaceRole[]>(() => {
    if (currentMember?.role === 'owner') return ['admin', 'contributor', 'viewer']
    return ['contributor', 'viewer']
  }, [currentMember?.role])

  async function toggleRole(roleId: string) {
    if (!selected || !canManageRoles || selected.role === 'owner') return
    const roleIds = selected.customRoleIds.includes(roleId)
      ? selected.customRoleIds.filter(id => id !== roleId)
      : [...selected.customRoleIds, roleId]
    setSavingRoles(true)
    try { await setMemberRoles(selected.id, roleIds) }
    catch (error) { pushToast(error instanceof Error ? error.message : 'Could not update roles.', 'danger') }
    finally { setSavingRoles(false) }
  }

  async function updateBaseRole(role: WorkspaceRole) {
    if (!selected || !canManageSelected || role === selected.role) return
    setSavingAccess(true)
    try { await changeMemberRole(selected.id, role) }
    catch (error) { pushToast(error instanceof Error ? error.message : 'Could not update member access.', 'danger') }
    finally { setSavingAccess(false) }
  }

  async function reportSelected() {
    if (!selected || selected.profileId === profile?.id) return
    const reason = window.prompt('Reason for reporting this member?')?.trim()
    if (!reason) return
    const details = window.prompt('Add any context for moderators (optional).')?.trim() ?? ''
    setReporting(true)
    try { await reportUser(selected.profileId, reason, details) }
    catch (error) { pushToast(error instanceof Error ? error.message : 'Could not send report.', 'danger') }
    finally { setReporting(false) }
  }

  async function kickMember() {
    if (!selected || !canManageSelected) return
    if (!window.confirm(`Remove ${selected.displayName} from this Space?`)) return
    setSavingAccess(true)
    try { await removeMember(selected.id); setSelectedId('') }
    catch (error) { pushToast(error instanceof Error ? error.message : 'Could not remove that member.', 'danger') }
    finally { setSavingAccess(false) }
  }

  function presenceFor(member: NonNullable<typeof selected>) {
    return member.profileId === profile?.id ? effectivePresence : member.status === 'away' ? 'idle' : member.status
  }

  function presenceLabel(member: NonNullable<typeof selected>) {
    const status = presenceFor(member)
    if (status === 'dnd') return 'Do Not Disturb'
    if (status === 'idle') return 'Idle'
    if (status === 'offline') return 'Offline'
    return 'Online'
  }

  return (
    <div className="members-view view-scroll page-enter members-view-v9">
      <div className="content-heading">
        <div><span className="eyebrow">COMMUNITY</span><h1>People</h1><p>Members, roles and contributions inside this Space.</p></div>
        <span className="big-count">{members.length}</span>
      </div>

      <div className="members-layout">
        <section className="member-grid">
          {members.map(member => {
            const memberRoles = roles.filter(role => member.customRoleIds.includes(role.id))
            const topRole = memberRoles[0]
            const status = presenceFor(member)
            return (
              <button className={`member-card member-card-profile ${selected?.id === member.id ? 'active' : ''}`} key={member.id} onClick={() => setSelectedId(member.id)}>
                <div
                  className={`member-card-banner-strip ${member.bannerUrl ? 'has-banner' : ''}`}
                  style={member.bannerUrl
                    ? { backgroundImage: `linear-gradient(to bottom, rgba(7,7,10,.04), rgba(7,7,10,.74)), url(${member.bannerUrl})` }
                    : { '--member-card-accent': member.profileAccent } as CSSProperties}
                  aria-hidden="true"
                />
                <div className="member-card-top">
                  <span className="profile-avatar-presence"><Avatar name={member.displayName} initials={member.initials} src={member.avatarUrl} size={50} accent={topRole?.color} /><i className={`presence-symbol presence-${status}`} /></span>
                  {member.platformRole && <span className={`member-platform-chip platform-${member.platformRole}`}><Icon name="shield" size={11}/>{platformRoleLabel(member.platformRole)}</span>}
                </div>
                <strong style={topRole ? { color: topRole.color } : undefined}>{member.displayName}</strong>
                <span>@{member.username}</span>
                <div className="member-role-row"><span className={`legacy-role role-${member.role}`}>{workspaceRoleLabel(member.role)}</span>{topRole && <span className="top-role-name">{topRole.name}</span>}</div>
              </button>
            )
          })}
        </section>

        <aside className="member-detail member-detail-v9">
          {selected ? <>
            <div className="member-detail-hero" style={selected.bannerUrl ? { backgroundImage: `linear-gradient(to bottom, rgba(8,8,12,.16), rgba(8,8,12,.94)), url(${selected.bannerUrl})`, backgroundSize: 'cover', backgroundPosition: 'center' } : { '--member-profile-accent': selected.profileAccent } as CSSProperties}>
              <button className="member-message-top" onClick={() => pushToast('Direct Messages are ready for the upcoming realtime messaging backend.', 'info')}><Icon name="chat" size={14}/> Message</button>
              <div className="member-detail-avatar profile-avatar-presence"><Avatar name={selected.displayName} initials={selected.initials} src={selected.avatarUrl} size={78} accent={selectedRoles[0]?.color}/><i className={`presence-symbol presence-${presenceFor(selected)}`} /></div>
              <div className="member-detail-name-row"><h2>{selected.displayName}</h2></div>
              <span>@{selected.username}</span>
              <span className={`presence-text presence-text-${presenceFor(selected)}`}>{presenceLabel(selected)}</span>
              {selected.profileId === profile?.id && preferences.customStatus && <p className="member-detail-custom-status">{preferences.customStatus}</p>}
              {selected.bio && <p className="member-detail-bio">{selected.bio}</p>}
              {selected.platformRole && <span className={`founder-badge platform-${selected.platformRole}`}><Icon name="shield" size={12}/>{platformRoleLabel(selected.platformRole)}</span>}
            </div>

            <details className="detail-section roles-profile-section profile-submenu" open>
              <summary><span><Icon name="roles" size={14}/><strong>Roles</strong></span><span>{1 + selectedRoles.length + (selected.platformRole ? 1 : 0)}</span></summary>
              <div className="profile-submenu-body">
                <div className="detail-section-title"><span className="eyebrow">SERVER ROLES</span>{selected.role === 'owner' && <span className="protected-role-note"><Icon name="lock" size={11}/> Protected</span>}</div>
                <div className="profile-role-chips">
                  {selected.platformRole && <span className={`profile-role-chip platform-role-chip platform-${selected.platformRole}`}><Icon name="shield" size={12}/>{platformRoleLabel(selected.platformRole)}</span>}
                  <span className={`profile-role-chip base role-${selected.role}`}><Icon name={selected.role === 'owner' ? 'shield' : 'roles'} size={12}/>{workspaceRoleLabel(selected.role)}</span>
                  {selectedRoles.map(role => <span className="profile-role-chip" key={role.id} style={{ color: role.color, borderColor: role.color }}><i style={{ background: role.color }}/>{role.name}</span>)}
                </div>
                {!selectedRoles.length && selected.role !== 'owner' && <p className="muted-copy">No additional roles assigned.</p>}
                {canManageSelected && <label className="member-access-control role-access-control"><span>Server role</span><GlassSelect disabled={savingAccess} ariaLabel="Server role" value={selected.role} options={[...(!baseRoleOptions.includes(selected.role) ? [selected.role] : []), ...baseRoleOptions].map(role => ({ value: role, label: workspaceRoleLabel(role) }))} onChange={value => void updateBaseRole(value as WorkspaceRole)} /></label>}
                {canManageRoles && roles.length > 0 && selected.role !== 'owner' && <div className="role-check-list compact-role-picker">
                  {roles.map(role => <label key={role.id}><input type="checkbox" disabled={savingRoles} checked={selected.customRoleIds.includes(role.id)} onChange={() => void toggleRole(role.id)} /><span className="role-swatch" style={{ background: role.color }}/><span>{role.name}</span>{selected.customRoleIds.includes(role.id) && <Icon name="check" size={14}/>}</label>)}
                </div>}
              </div>
            </details>

            <div className="detail-section contributions-section">
              <span className="eyebrow">CONTRIBUTIONS</span>
              {contributions.length ? <div className="contribution-list">{contributions.map(item => <button key={item.id} onClick={() => chooseChannel(item.channelId)}><span className="contribution-icon"><Icon name="notes" size={14}/></span><span><strong>{item.title}</strong><small>{item.action} · v{item.version} · {timeAgo(item.updatedAt)}</small></span><Icon name="chevron" size={13}/></button>)}</div> : <p className="muted-copy">No note contributions yet.</p>}
            </div>

            {(canManageSelected || selected.profileId !== profile?.id) && <div className="detail-section member-management-v9">
              <span className="eyebrow">ACTIONS</span>
              <div className="member-action-row">{selected.profileId !== profile?.id && <button className="secondary-button compact" disabled={reporting} onClick={() => void reportSelected()}><Icon name="shield" size={14}/> Report</button>}{canManageSelected && <button className="ghost-danger" disabled={savingAccess} onClick={() => void kickMember()}><Icon name="trash" size={14}/> Remove member</button>}</div>
            </div>}
          </> : <div className="mini-empty tall"><Icon name="members"/><span>Select a member.</span></div>}
        </aside>
      </div>
    </div>
  )
}
