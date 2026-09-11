import { Icon } from './Icon'
import { SpacesLogo } from './SpacesLogo'
import { usePreferences } from '../state/PreferencesContext'
import { useSpaces } from '../state/SpacesContext'
import { timeAgo } from '../utils/format'

export function NotificationCenter({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { notifications, clearNotifications, chooseWorkspace, chooseChannel } = useSpaces()
  const { preferences } = usePreferences()
  const visible = notifications.filter(item => preferences.notificationLevel !== 'none' && (preferences.notificationLevel === 'all' || item.kind !== 'message') && !preferences.mutedWorkspaceIds.includes(item.workspaceId) && !preferences.mutedChannelIds.includes(item.channelId))

  async function openNotification(workspaceId: string, channelId: string) {
    await chooseWorkspace(workspaceId)
    chooseChannel(channelId)
    onClose()
  }

  if (!open) return null
  return <>
    <button className="notification-center-scrim" aria-label="Close notifications" onPointerDown={onClose} />
    <aside className="notification-center page-enter" aria-label="Notifications">
      <header>
        <div><span className="eyebrow">INBOX</span><strong>Notifications</strong></div>
        <div>{visible.length > 0 && <button className="notification-clear" onClick={clearNotifications}>Mark all read</button>}<button className="icon-button" onClick={onClose}><Icon name="x" size={15}/></button></div>
      </header>
      <div className="notification-center-list">
        {visible.map(item => <button className="notification-card" key={item.id} onClick={() => void openNotification(item.workspaceId, item.channelId)}>
          <span className="notification-card-icon notification-spaces-mark"><SpacesLogo title="Spaces notification" /></span>
          <div><div><strong>{item.authorName}</strong><time>{timeAgo(item.createdAt)}</time></div><span>{item.workspaceName} · #{item.channelName} · {item.kind === 'message' ? 'message' : item.mentionLabel}</span><p>{item.preview}</p></div>
          <Icon name="chevron" size={14}/>
        </button>)}
        {!visible.length && <div className="notification-empty"><span className="notification-empty-icon notification-spaces-mark"><SpacesLogo title="Spaces" /></span><strong>You're all caught up</strong><p>Mentions and important activity will collect here.</p></div>}
      </div>
    </aside>
  </>
}
