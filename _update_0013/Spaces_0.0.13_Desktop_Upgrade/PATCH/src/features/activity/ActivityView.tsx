import { useMemo, useState } from 'react'
import { Avatar } from '../../components/Avatar'
import { Icon, type IconName } from '../../components/Icon'
import { useSpaces } from '../../state/SpacesContext'
import type { WorkspaceAuditAction } from '../../types/spaces'
import { timeAgo } from '../../utils/format'

const actionMeta: Partial<Record<WorkspaceAuditAction, { icon: IconName; label: string }>> = {
  'workspace.created': { icon: 'grid', label: 'created the Space' },
  'channel.created': { icon: 'hash', label: 'created a channel' },
  'note.created': { icon: 'notes', label: 'created a note' },
  'note.edited': { icon: 'edit', label: 'edited a note' },
  'note.deleted': { icon: 'trash', label: 'deleted a note' },
  'member.joined': { icon: 'members', label: 'joined the Space' },
  'member.role_changed': { icon: 'roles', label: 'changed member access' },
  'member.removed': { icon: 'members', label: 'removed a member' },
  'settings.changed': { icon: 'settings', label: 'changed Space settings' },
  'message.edited': { icon: 'edit', label: 'edited a message' },
  'message.deleted': { icon: 'trash', label: 'removed a message' },
  'role.created': { icon: 'roles', label: 'created a role' },
  'role.updated': { icon: 'roles', label: 'updated a role' },
  'role.deleted': { icon: 'trash', label: 'deleted a role' },
  'member.custom_roles_changed': { icon: 'shield', label: 'updated custom roles' },
  'emoji.created': { icon: 'emoji', label: 'added an emoji' },
  'emoji.deleted': { icon: 'emoji', label: 'removed an emoji' },
  'comment.created': { icon: 'reply', label: 'commented on a note' },
  'comment.edited': { icon: 'edit', label: 'edited a comment' },
  'comment.deleted': { icon: 'trash', label: 'removed a comment' },
}

export function ActivityView() {
  const { data } = useSpaces()
  const [filter, setFilter] = useState<'all' | 'content' | 'people' | 'settings'>('all')

  const logs = useMemo(() => {
    const source = [...(data?.logs ?? [])].sort((a, b) => b.createdAt - a.createdAt)
    if (filter === 'all') return source
    if (filter === 'content') return source.filter(log => /note|message|comment|emoji/.test(log.action))
    if (filter === 'people') return source.filter(log => /member|role|report|ban/.test(log.action))
    return source.filter(log => /workspace|settings|channel/.test(log.action))
  }, [data?.logs, filter])

  const membersById = useMemo(() => new Map((data?.members ?? []).map(member => [member.profileId, member])), [data?.members])

  return (
    <div className="view-scroll activity-view page-enter">
      <div className="content-heading activity-heading">
        <div><span className="eyebrow">HISTORY</span><h1>Activity</h1><p>A clean audit trail for this Space.</p></div>
        <div className="activity-filter segmented-control">
          {(['all', 'content', 'people', 'settings'] as const).map(item => <button key={item} className={filter === item ? 'active' : ''} onClick={() => setFilter(item)}>{item}</button>)}
        </div>
      </div>

      <section className="activity-timeline">
        {logs.map(log => {
          const meta = actionMeta[log.action] ?? { icon: 'activity' as IconName, label: log.action.replaceAll('.', ' ') }
          const member = membersById.get(log.actorId)
          return (
            <article className="activity-item" key={log.id}>
              <div className="activity-spine"><span><Icon name={meta.icon} size={15} /></span><i /></div>
              <Avatar name={log.actorName} initials={member?.initials} src={member?.avatarUrl} size={34} />
              <div className="activity-copy">
                <p><strong>{log.actorName}</strong> {meta.label}{log.targetLabel ? <> <b>{log.targetLabel}</b></> : null}</p>
                {log.reason && <span>{log.reason}</span>}
                <time>{timeAgo(log.createdAt)}</time>
              </div>
            </article>
          )
        })}
        {!logs.length && <div className="center-empty inline-empty"><Icon name="activity" /><h2>No activity yet</h2><p>Space changes will show up here.</p></div>}
      </section>

      {(data?.updates.length ?? 0) > 0 && (
        <section className="release-strip">
          <div><Icon name="sparkle" /><span><strong>Spaces updates</strong><small>Backend release notes available to this client.</small></span></div>
          <div className="release-chips">{data?.updates.slice(0, 3).map(update => <span key={update.version}>v{update.version} · {update.title}</span>)}</div>
        </section>
      )}
    </div>
  )
}
