import { useMemo } from 'react'
import { Avatar } from '../../components/Avatar'
import { Icon } from '../../components/Icon'
import { usePreferences } from '../../state/PreferencesContext'
import { useSpaces } from '../../state/SpacesContext'
import { timeAgo } from '../../utils/format'
import { filterContent } from '../../utils/content-filter'
import { hasWorkspacePermission } from '../../utils/permissions'

export function WorkspaceOverview() {
  const { data, profile, activeWorkspace, chooseChannel, setView } = useSpaces()
  const { preferences } = usePreferences()

  const stats = useMemo(() => {
    const messages = (data?.messages ?? []).filter(message => !message.deletedAt)
    const notes = data?.notes ?? []
    const online = (data?.members ?? []).filter(member => member.status !== 'offline')
    return {
      messages: messages.length,
      notes: notes.length,
      members: data?.members.length ?? 0,
      online: online.length,
      roles: data?.roles.length ?? 0,
      emojis: data?.emojis.length ?? 0,
    }
  }, [data])

  const recentMessages = useMemo(
    () => [...(data?.messages ?? [])]
      .filter(message => !message.deletedAt)
      .sort((a, b) => b.createdAt - a.createdAt)
      .slice(0, 5),
    [data?.messages],
  )

  const recentNotes = useMemo(
    () => [...(data?.notes ?? [])].sort((a, b) => b.updatedAt - a.updatedAt).slice(0, 4),
    [data?.notes],
  )

  const onlineMembers = useMemo(
    () => (data?.members ?? []).filter(member => member.status !== 'offline').slice(0, 8),
    [data?.members],
  )

  if (!activeWorkspace || !data) return null

  const canInvite = hasWorkspacePermission(data, profile?.id, 'create_invites')
  const firstChat = data.channels.find(channel => channel.kind !== 'notes')
  const firstNotes = data.channels.find(channel => channel.kind === 'notes')

  return (
    <div className="view-scroll workspace-overview page-enter">
      <section className="space-overview-hero">
        <div
          className="space-overview-banner"
          style={activeWorkspace.bannerUrl ? { backgroundImage: `url(${activeWorkspace.bannerUrl})` } : undefined}
        >
          <div className="space-overview-glow" />
        </div>
        <div className="space-overview-content">
          <Avatar
            name={activeWorkspace.name}
            initials={activeWorkspace.initials}
            src={activeWorkspace.avatarUrl}
            size={76}
            accent={activeWorkspace.accentColor}
          />
          <div className="space-overview-title">
            <span className="eyebrow">YOUR SPACE</span>
            <h1>{activeWorkspace.name}</h1>
            <p>{activeWorkspace.description || 'A shared place for conversations, notes and the people behind them.'}</p>
            <div className="space-overview-meta">
              <span><i className="presence-pip online" /> {stats.online} online</span>
              <span>{stats.members} members</span>
              <span>{data.channels.length} channels</span>
            </div>
          </div>
          <div className="space-overview-actions">
            {firstChat && (
              <button className="primary-button" onClick={() => chooseChannel(firstChat.id)}>
                <Icon name="chat" size={16} /> Open chat
              </button>
            )}
            {firstNotes && (
              <button className="secondary-button" onClick={() => chooseChannel(firstNotes.id)}>
                <Icon name="notes" size={16} /> Open notes
              </button>
            )}
          </div>
        </div>
      </section>

      <section className="overview-stat-grid" aria-label="Space statistics">
        <button onClick={() => setView('members')}><Icon name="members" /><strong>{stats.members}</strong><span>People</span><small>{stats.online} active now</small></button>
        <button onClick={() => firstChat && chooseChannel(firstChat.id)}><Icon name="chat" /><strong>{stats.messages}</strong><span>Messages</span><small>Across loaded channels</small></button>
        <button onClick={() => firstNotes && chooseChannel(firstNotes.id)}><Icon name="notes" /><strong>{stats.notes}</strong><span>Notes</span><small>Shared knowledge</small></button>
        <button onClick={() => setView('roles')}><Icon name="roles" /><strong>{stats.roles}</strong><span>Custom roles</span><small>{stats.emojis} custom emoji</small></button>
      </section>

      <section className="overview-columns">
        <article className="overview-panel overview-panel-wide">
          <header className="overview-panel-heading">
            <div><span className="eyebrow">RECENT</span><h2>Conversation</h2></div>
            {firstChat && <button onClick={() => chooseChannel(firstChat.id)}>View chat <Icon name="chevron" size={13} /></button>}
          </header>
          <div className="overview-feed">
            {recentMessages.map(message => {
              const channel = data.channels.find(item => item.id === message.channelId)
              return (
                <button className="overview-message" key={message.id} onClick={() => chooseChannel(message.channelId)}>
                  <Avatar name={message.authorName} initials={message.authorInitials} size={34} />
                  <div>
                    <div><strong>{message.authorName}</strong><span>#{channel?.name ?? 'channel'} · {timeAgo(message.createdAt)}</span></div>
                    <p>{filterContent(message.body, preferences.contentFilter) || (message.attachment ? `Shared ${message.attachment.name}` : 'Message')}</p>
                  </div>
                </button>
              )
            })}
            {!recentMessages.length && <div className="overview-empty"><Icon name="chat" /><span>No messages yet. Start the first conversation.</span></div>}
          </div>
        </article>

        <article className="overview-panel">
          <header className="overview-panel-heading"><div><span className="eyebrow">KNOWLEDGE</span><h2>Recently edited</h2></div></header>
          <div className="overview-note-list">
            {recentNotes.map(note => {
              const channel = data.channels.find(item => item.id === note.channelId)
              return (
                <button key={note.id} onClick={() => chooseChannel(note.channelId)}>
                  <span className="overview-note-icon"><Icon name="notes" size={15} /></span>
                  <div><strong>{note.title}</strong><span>#{channel?.name ?? 'notes'} · {timeAgo(note.updatedAt)}</span></div>
                  <Icon name="chevron" size={13} />
                </button>
              )
            })}
            {!recentNotes.length && <div className="overview-empty compact"><Icon name="notes" /><span>No notes yet.</span></div>}
          </div>
        </article>
      </section>

      <section className="overview-bottom-grid">
        <article className="overview-panel people-now-panel">
          <header className="overview-panel-heading"><div><span className="eyebrow">NOW</span><h2>People around</h2></div><button onClick={() => setView('members')}>All people</button></header>
          <div className="people-now-row">
            {onlineMembers.map(member => (
              <button key={member.id} title={member.displayName} onClick={() => setView('members')}>
                <span className="avatar-wrap"><Avatar name={member.displayName} initials={member.initials} src={member.avatarUrl} size={38} /><i className={`status-dot status-${member.status}`} /></span>
                <span>{member.displayName.split(' ')[0]}</span>
              </button>
            ))}
            {!onlineMembers.length && <div className="overview-empty compact"><Icon name="members" /><span>Quiet right now.</span></div>}
          </div>
        </article>

        <article className="overview-panel overview-shortcuts">
          <header className="overview-panel-heading"><div><span className="eyebrow">SPACE TOOLS</span><h2>Manage</h2></div></header>
          <div className="overview-tool-grid">
            <button onClick={() => setView('activity')}><Icon name="activity" /><span>Activity</span></button>
            {canInvite && <button onClick={() => setView('invites')}><Icon name="plus" /><span>Invites</span></button>}
            <button onClick={() => setView('emoji')}><Icon name="emoji" /><span>Emoji</span></button>
            <button onClick={() => setView('settings')}><Icon name="settings" /><span>Settings</span></button>
          </div>
        </article>
      </section>
    </div>
  )
}
