import { Icon } from '../../components/Icon'
import { useSpaces } from '../../state/SpacesContext'
import { hasWorkspacePermission } from '../../utils/permissions'

export function StaffView() {
  const { data, profile, setView } = useSpaces()
  const canModerate = hasWorkspacePermission(data, profile?.id, 'moderate_messages') || hasWorkspacePermission(data, profile?.id, 'moderate_comments')
  const canMembers = hasWorkspacePermission(data, profile?.id, 'manage_members')
  const canRoles = hasWorkspacePermission(data, profile?.id, 'manage_roles')
  const canAudit = hasWorkspacePermission(data, profile?.id, 'view_audit_log')
  if (!canModerate && !canMembers && !canRoles && !canAudit) return <div className="view-scroll page-enter"><div className="empty-state"><Icon name="lock"/><h3>Staff only</h3><p>You do not have permission to open this area.</p></div></div>
  return <div className="view-scroll staff-view page-enter">
    <div className="content-heading"><div><span className="eyebrow">STAFF WORKSPACE</span><h1>Staff</h1><p>Moderation, permissions and operational tools for this Space.</p></div><span className="staff-secure-chip"><Icon name="shield" size={14}/> Permission gated</span></div>
    <div className="staff-tool-grid">
      {canMembers && <button onClick={() => setView('members')}><Icon name="members"/><div><strong>Member management</strong><span>Review members, roles, reports and removals.</span></div><Icon name="chevron" size={15}/></button>}
      {canRoles && <button onClick={() => setView('roles')}><Icon name="roles"/><div><strong>Roles & permissions</strong><span>Build staff roles and control access.</span></div><Icon name="chevron" size={15}/></button>}
      {canAudit && <button onClick={() => setView('activity')}><Icon name="activity"/><div><strong>Audit log</strong><span>Review administrative activity and moderation actions.</span></div><Icon name="chevron" size={15}/></button>}
      <button onClick={() => setView('settings')}><Icon name="settings"/><div><strong>Channel access</strong><span>Control who can post or edit in each channel.</span></div><Icon name="chevron" size={15}/></button>
    </div>
    <section className="staff-callout"><Icon name="shield"/><div><strong>Moderation should be quiet.</strong><p>Removed messages disappear from public chat. Staff actions stay reviewable in audit logs instead of leaving public tombstones.</p></div></section>
  </div>
}
