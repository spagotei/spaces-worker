import { useState, type CSSProperties } from 'react'
import { Avatar } from '../../components/Avatar'
import { Icon } from '../../components/Icon'
import { Modal } from '../../components/Modal'
import { useSpaces } from '../../state/SpacesContext'
import { usePreferences } from '../../state/PreferencesContext'
import { timeAgo } from '../../utils/format'

export function HomeView() {
  const { profile, workspaces, notifications, clearNotifications, chooseWorkspace, createWorkspace, joinWorkspace } = useSpaces()
  const { preferences, setPreference } = usePreferences()
  const [dialog, setDialog] = useState<'create' | 'join' | null>(null)
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)
  const visibleWorkspaces = workspaces.filter(space => !preferences.hiddenWorkspaceIds.includes(space.id))
  const hiddenWorkspaces = workspaces.filter(space => preferences.hiddenWorkspaceIds.includes(space.id))
  const visibleNotifications = notifications.filter(item => !preferences.mutedWorkspaceIds.includes(item.workspaceId) && !preferences.mutedChannelIds.includes(item.channelId))
  const firstNotification = visibleNotifications[0]

  function openNotifications() {
    window.dispatchEvent(new CustomEvent('spaces-open-notifications'))
  }

  async function submit() {
    if (!value.trim()) return
    setBusy(true)
    try {
      if (dialog === 'create') await createWorkspace(value.trim())
      if (dialog === 'join') await joinWorkspace(value.trim())
      setDialog(null)
      setValue('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="view-scroll home-view page-enter">
      <section className="hero-panel">
        <div className="hero-copy">
          <span className="eyebrow">GOOD TO SEE YOU</span>
          <h1>{profile?.displayName ?? 'Welcome'}<span className="hero-dot">.</span></h1>
          <p>Pick up where your team left off, jump into a conversation, or build a new Space around the next thing.</p>
          <div className="hero-actions">
            <button className="primary-button" onClick={() => setDialog('create')}><Icon name="plus" size={16} /> New Space</button>
            <button className="secondary-button" onClick={() => setDialog('join')}><Icon name="grid" size={16} /> Join with code</button>
          </div>
        </div>
        <aside className={`hero-missed ${visibleNotifications.length ? 'has-items' : ''}`} onClick={visibleNotifications.length ? openNotifications : undefined}>
          <div className="hero-missed-head"><span><Icon name="bell" size={15}/> SEE WHAT YOU MISSED</span><strong>{visibleNotifications.length ? `${visibleNotifications.length} update${visibleNotifications.length === 1 ? '' : 's'}` : 'All clear'}</strong></div>
          {firstNotification ? <>
            <p><b>{firstNotification.authorName}</b> mentioned you in {firstNotification.workspaceName}: “{firstNotification.preview}”</p>
            <div className="hero-missed-actions">
              <button onClick={event => { event.stopPropagation(); openNotifications() }}>View notifications <Icon name="chevron" size={14}/></button>
              <button onClick={event => { event.stopPropagation(); clearNotifications() }}>Clear</button>
            </div>
          </> : <>
            <p>No unread mentions yet. Replies, @mentions and important activity can surface here.</p>
            <button onClick={() => visibleWorkspaces[0] && void chooseWorkspace(visibleWorkspaces[0].id)} disabled={!visibleWorkspaces.length}>Jump back in <Icon name="chevron" size={14}/></button>
          </>}
        </aside>
      </section>

      <section className="section-block">
        <div className="section-heading"><div><span className="eyebrow">JUMP BACK IN</span><h2>Your Spaces</h2></div><span className="section-count">{visibleWorkspaces.length}</span></div>
        {visibleWorkspaces.length ? (
          <div className="space-card-grid">
            {visibleWorkspaces.map((space, index) => (
              <button className="space-card" key={space.id} onClick={() => void chooseWorkspace(space.id)} style={{ '--delay': `${index * 45}ms`, '--space-accent': space.accentColor } as CSSProperties}>
                <div className="space-card-banner" style={space.bannerUrl ? { backgroundImage: `url(${space.bannerUrl})` } : undefined} />
                <div className="space-card-body">
                  <span className={`space-icon-decor icon-decor-${space.iconDecoration ?? 'ring'}`} style={{ '--decor-accent': space.accentColor } as CSSProperties}><Avatar name={space.name} initials={space.initials} src={space.avatarUrl} size={46} accent={space.accentColor} /></span>
                  <div><strong>{space.name}</strong><span>{space.description || 'Shared Space'}</span></div>
                  <Icon name="chevron" size={17} className="card-chevron" />
                </div>
                <div className="space-card-meta"><span>{space.role}</span><span>Created {timeAgo(space.createdAt)}</span></div>
              </button>
            ))}
          </div>
        ) : (
          <div className="empty-state"><div className="empty-icon"><Icon name="grid" /></div><h3>No Spaces yet</h3><p>Create your first Space or join one with an invite code.</p></div>
        )}
      </section>

      {hiddenWorkspaces.length > 0 && <section className="hidden-spaces-strip">
        <div><Icon name="lock" size={14}/><span>{hiddenWorkspaces.length} hidden Space{hiddenWorkspaces.length === 1 ? '' : 's'}</span></div>
        <div>{hiddenWorkspaces.map(space => <button key={space.id} onClick={() => setPreference('hiddenWorkspaceIds', preferences.hiddenWorkspaceIds.filter(id => id !== space.id))}>Show {space.name}</button>)}</div>
      </section>}

      <section className="dashboard-strip">
        <article><Icon name="chat" /><div><strong>Conversations</strong><span>Chat, custom emoji and files in one place.</span></div></article>
        <article><Icon name="notes" /><div><strong>Shared notes</strong><span>Collaborate without turning every thought into a message.</span></div></article>
        <article><Icon name="roles" /><div><strong>Real permissions</strong><span>Stackable roles and fine-grained moderation controls.</span></div></article>
      </section>

      {dialog && (
        <Modal title={dialog === 'create' ? 'Create a Space' : 'Join a Space'} subtitle={dialog === 'create' ? 'Give your team somewhere to land.' : 'Paste a Space code or invite code.'} onClose={() => setDialog(null)}>
          <label className="field-label">{dialog === 'create' ? 'Space name' : 'Invite code'}<input className="text-input" autoFocus value={value} onChange={e => setValue(e.target.value)} onKeyDown={e => e.key === 'Enter' && void submit()} placeholder={dialog === 'create' ? 'Midnight Studio' : 'ABC123'} /></label>
          <div className="modal-actions"><button className="secondary-button" onClick={() => setDialog(null)}>Cancel</button><button className="primary-button" disabled={busy || !value.trim()} onClick={() => void submit()}>{busy ? 'Working…' : dialog === 'create' ? 'Create Space' : 'Join Space'}</button></div>
        </Modal>
      )}
    </div>
  )
}
