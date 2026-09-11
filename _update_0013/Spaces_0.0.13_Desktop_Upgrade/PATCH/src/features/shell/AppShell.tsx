import { useEffect, useMemo, useState, type CSSProperties } from 'react'
import { Avatar } from '../../components/Avatar'
import { SpacesLogo } from '../../components/SpacesLogo'
import { Icon, type IconName } from '../../components/Icon'
import { Modal } from '../../components/Modal'
import { NotificationCenter } from '../../components/NotificationCenter'
import { ContextMenu, useContextMenu, type ContextAction } from '../../components/ContextMenu'
import { ChannelPermissionsEditor } from '../../components/ChannelPermissionsEditor'
import { ActivityView } from '../activity/ActivityView'
import { ChatView } from '../chat/ChatView'
import { EmojiView } from '../emoji/EmojiView'
import { HomeView } from '../home/HomeView'
import { InvitesView } from '../invites/InvitesView'
import { MembersView } from '../members/MembersView'
import { NotesView } from '../notes/NotesView'
import { RolesView } from '../roles/RolesView'
import { SettingsView } from '../settings/SettingsView'
import { WorkspaceOverview } from '../overview/WorkspaceOverview'
import { PersonalSettings } from '../account/PersonalSettings'
import { StaffView } from '../staff/StaffView'
import { useSpaces, type AppView, type SpacesNotification } from '../../state/SpacesContext'
import { usePreferences } from '../../state/PreferencesContext'
import { normalizeChannelName } from '../../utils/format'
import { hasWorkspacePermission, platformRoleLabel, workspaceRoleLabel } from '../../utils/permissions'
import type { WorkspaceChannel, WorkspaceSummary } from '../../types/spaces'

const navItems: { view: AppView; label: string; icon: IconName }[] = [
  { view: 'members', label: 'People', icon: 'members' },
  { view: 'emoji', label: 'Emoji', icon: 'emoji' },
  { view: 'activity', label: 'Activity', icon: 'activity' },
  { view: 'invites', label: 'Invites', icon: 'plus' },
  { view: 'settings', label: 'Settings', icon: 'settings' },
]

export function AppShell() {
  const { effectivePresence, preferences, setPreference } = usePreferences()
  const contextMenu = useContextMenu()
  const {
    profile, workspaces, activeWorkspaceId, activeWorkspace, data, activeChannel, view,
    memberRailOpen, mobileNavOpen, commandOpen, workspaceLoading, toasts, notifications,
    goHome, chooseWorkspace, chooseChannel, setView, setMemberRailOpen, setMobileNavOpen,
    setCommandOpen, createWorkspace, joinWorkspace, createChannel, deleteChannel, updateChannelPermissions, pushToast,
  } = useSpaces()
  const [spaceDialog, setSpaceDialog] = useState<'create' | 'join' | null>(null)
  const [spaceValue, setSpaceValue] = useState('')
  const [channelDialog, setChannelDialog] = useState(false)
  const [channelName, setChannelName] = useState('')
  const [channelDescription, setChannelDescription] = useState('')
  const [channelKind, setChannelKind] = useState<'chat' | 'notes' | 'mixed' | 'announcement'>('chat')
  const [busy, setBusy] = useState(false)
  const [profileDialog, setProfileDialog] = useState(false)
  const [accountMenuOpen, setAccountMenuOpen] = useState(false)
  const [previewBackground, setPreviewBackground] = useState<string | null>(null)
  const [selectedRailMember, setSelectedRailMember] = useState<string | null>(null)
  const [notificationOpen, setNotificationOpen] = useState(false)
  const [noticePeek, setNoticePeek] = useState<SpacesNotification | null>(null)
  const [channelPermissionTarget, setChannelPermissionTarget] = useState<WorkspaceChannel | null>(null)
  const [, forceTheme] = useState(0)
  useEffect(() => { const rerender = () => forceTheme(value => value + 1); window.addEventListener('spaces-theme-updated', rerender); return () => window.removeEventListener('spaces-theme-updated', rerender) }, [])
  useEffect(() => { document.title = 'Spaces' }, [])
  useEffect(() => { const preview = (event: Event) => setPreviewBackground((event as CustomEvent<string>).detail); window.addEventListener('spaces-background-preview', preview); return () => window.removeEventListener('spaces-background-preview', preview) }, [])
  useEffect(() => setPreviewBackground(null), [activeWorkspaceId])
  useEffect(() => { const open = () => setNotificationOpen(true); window.addEventListener('spaces-open-notifications', open); return () => window.removeEventListener('spaces-open-notifications', open) }, [])
  useEffect(() => { let timer = 0; const show = (event: Event) => { const item = (event as CustomEvent<SpacesNotification>).detail; const mention = item.kind !== 'message'; if (preferences.notificationLevel === 'none' || (preferences.notificationLevel === 'mentions' && !mention) || preferences.mutedWorkspaceIds.includes(item.workspaceId) || preferences.mutedChannelIds.includes(item.channelId) || preferences.presence === 'dnd') return; setNoticePeek(item); if (preferences.desktopSounds) { try { const AudioContextClass = window.AudioContext || (window as typeof window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext; if (AudioContextClass) { const context = new AudioContextClass(); const oscillator = context.createOscillator(); const gain = context.createGain(); oscillator.frequency.value = 620; gain.gain.setValueAtTime(.025, context.currentTime); gain.gain.exponentialRampToValueAtTime(.0001, context.currentTime + .16); oscillator.connect(gain); gain.connect(context.destination); oscillator.start(); oscillator.stop(context.currentTime + .16); oscillator.addEventListener('ended', () => void context.close()); } } catch { /* Sound is optional. */ } } window.clearTimeout(timer); timer = window.setTimeout(() => setNoticePeek(null), 5200) }; window.addEventListener('spaces-notification-peek', show); return () => { window.clearTimeout(timer); window.removeEventListener('spaces-notification-peek', show) } }, [preferences.desktopSounds, preferences.mutedChannelIds, preferences.mutedWorkspaceIds, preferences.notificationLevel, preferences.presence])

  const canCreateChannel = hasWorkspacePermission(data, profile?.id, 'create_channels')
  const canManageChannels = hasWorkspacePermission(data, profile?.id, 'manage_channels')
  const canManageSpace = hasWorkspacePermission(data, profile?.id, 'manage_space')
  const canInvite = hasWorkspacePermission(data, profile?.id, 'create_invites')
  const canStaff = hasWorkspacePermission(data, profile?.id, 'manage_roles') || hasWorkspacePermission(data, profile?.id, 'manage_members') || hasWorkspacePermission(data, profile?.id, 'moderate_messages') || hasWorkspacePermission(data, profile?.id, 'view_audit_log')
  const background = previewBackground ?? activeWorkspace?.background ?? 'graphite'
  const secondaryAccent = activeWorkspaceId ? (localStorage.getItem(`spaces.theme2.${activeWorkspaceId}`) || '#342044') : '#342044'
  const visibleWorkspaces = workspaces.filter(space => !preferences.hiddenWorkspaceIds.includes(space.id))
  const visibleNotifications = notifications.filter(item => preferences.notificationLevel !== 'none' && (preferences.notificationLevel === 'all' || item.kind !== 'message') && !preferences.mutedWorkspaceIds.includes(item.workspaceId) && !preferences.mutedChannelIds.includes(item.channelId))
  const appStyle = {
    '--active-accent': preferences.appAccent,
    '--app-accent': preferences.appAccent,
    '--workspace-accent': activeWorkspace?.accentColor ?? preferences.appAccent,
    '--active-accent-2': secondaryAccent,
  } as CSSProperties



  async function openNotificationItem(item: SpacesNotification) {
    setNoticePeek(null)
    setNotificationOpen(false)
    await chooseWorkspace(item.workspaceId)
    chooseChannel(item.channelId)
  }

  function toggleInList(key: 'hiddenWorkspaceIds' | 'mutedWorkspaceIds' | 'mutedChannelIds', id: string) {
    const current = preferences[key]
    setPreference(key, current.includes(id) ? current.filter(item => item !== id) : [...current, id])
  }

  function workspaceActions(space: WorkspaceSummary): ContextAction[] {
    const muted = preferences.mutedWorkspaceIds.includes(space.id)
    const hidden = preferences.hiddenWorkspaceIds.includes(space.id)
    const isHub = space.id === 'spaces-hub'
    return [
      { id: 'open', label: 'Open Space', note: space.description || 'Open this Space', icon: 'grid', onSelect: () => void chooseWorkspace(space.id) },
      ...(space.id === activeWorkspaceId && canCreateChannel ? [{ id: 'new-channel', label: 'Create channel', note: 'Add a conversation, notes or announcement channel', icon: 'plus' as IconName, onSelect: async () => { if (space.id !== activeWorkspaceId) await chooseWorkspace(space.id); setChannelDialog(true) } }] : []),
      ...(space.id === activeWorkspaceId && canInvite ? [{ id: 'invite', label: 'Invite people', note: 'Open invite management', icon: 'members' as IconName, onSelect: async () => { if (space.id !== activeWorkspaceId) await chooseWorkspace(space.id); setView('invites') } }] : []),
      { id: 'mute', label: muted ? 'Unmute Space' : 'Mute Space', note: muted ? 'Resume mention alerts' : 'Silence notifications from this Space', icon: muted ? 'bell' : 'x', checked: muted, onSelect: () => toggleInList('mutedWorkspaceIds', space.id) },
      { id: 'hide', label: hidden ? 'Show Space' : 'Hide Space', note: isHub ? 'Keep Hub membership but remove it from your rail' : 'Remove it from your rail without leaving', icon: 'lock', checked: hidden, onSelect: () => toggleInList('hiddenWorkspaceIds', space.id) },
      ...(space.id === activeWorkspaceId && canManageSpace ? [{ id: 'settings', label: 'Space settings', note: 'Identity, artwork and permissions', icon: 'settings' as IconName, onSelect: () => setView('settings') }] : []),
      ...(isHub ? [{ id: 'hub', label: 'Permanent platform Space', note: 'Spaces - Hub cannot be left or deleted', icon: 'shield' as IconName, disabled: true, onSelect: () => undefined }] : []),
    ]
  }

  function channelActions(channel: WorkspaceChannel): ContextAction[] {
    const muted = preferences.mutedChannelIds.includes(channel.id)
    return [
      { id: 'open', label: 'Open channel', note: channel.description || channel.kind, icon: channel.kind === 'notes' ? 'notes' : 'hash', onSelect: () => chooseChannel(channel.id) },
      { id: 'mute', label: muted ? 'Unmute channel' : 'Mute channel', note: muted ? 'Resume notifications here' : 'Mentions stay in the channel but will not ping you', icon: 'bell', checked: muted, onSelect: () => toggleInList('mutedChannelIds', channel.id) },
      { id: 'copy', label: 'Copy channel name', note: `#${channel.name}`, icon: 'copy', onSelect: async () => { await navigator.clipboard.writeText(`#${channel.name}`); pushToast('Channel name copied.', 'success') } },
      ...(canManageChannels ? [
        { id: 'permissions', label: 'Channel permissions', note: 'Control who can post or edit notes', icon: 'shield' as IconName, onSelect: () => setChannelPermissionTarget(channel) },
        ...(channel.id !== 'spaces-hub-updates' ? [{ id: 'delete-channel', label: 'Delete channel', note: 'Removes its messages and notes', icon: 'trash' as IconName, danger: true, onSelect: async () => { if (!window.confirm(`Delete #${channel.name}? This removes content inside it.`)) return; try { await deleteChannel(channel.id) } catch (error) { pushToast(error instanceof Error ? error.message : 'Could not delete channel.', 'danger') } } }] : []),
      ] : []),
    ]
  }

  function categoryActions(label: string, channels: WorkspaceChannel[], kind: 'chat' | 'notes' | 'announcement') : ContextAction[] {
    const allMuted = channels.length > 0 && channels.every(channel => preferences.mutedChannelIds.includes(channel.id))
    return [
      ...(canCreateChannel ? [{ id: 'category-new', label: `New ${kind === 'notes' ? 'note' : kind === 'announcement' ? 'announcement' : 'conversation'} channel`, note: `Add to ${label}`, icon: 'plus' as IconName, onSelect: () => { setChannelKind(kind); setChannelDialog(true) } }] : []),
      ...(channels.length ? [{ id: 'category-mute', label: allMuted ? 'Unmute category' : 'Mute category', note: `${channels.length} channel${channels.length === 1 ? '' : 's'}`, icon: 'bell' as IconName, checked: allMuted, onSelect: () => { const ids = new Set(preferences.mutedChannelIds); channels.forEach(channel => allMuted ? ids.delete(channel.id) : ids.add(channel.id)); setPreference('mutedChannelIds', [...ids]) } }] : []),
      ...(canManageChannels && channels.length && !channels.some(channel => channel.id === 'spaces-hub-updates') ? [{ id: 'category-delete', label: 'Delete category', note: `Deletes all ${channels.length} channels in ${label}`, icon: 'trash' as IconName, danger: true, onSelect: async () => { if (!window.confirm(`Delete ${label} and all ${channels.length} channel${channels.length === 1 ? '' : 's'} inside it?`)) return; try { for (const channel of channels) await deleteChannel(channel.id); pushToast(`${label} deleted.`, 'success') } catch (error) { pushToast(error instanceof Error ? error.message : `Could not delete ${label}.`, 'danger') } } }] : []),
    ]
  }

  async function submitSpace() {
    if (!spaceValue.trim() || !spaceDialog) return
    setBusy(true)
    try {
      if (spaceDialog === 'create') await createWorkspace(spaceValue.trim())
      else await joinWorkspace(spaceValue.trim())
      setSpaceDialog(null)
      setSpaceValue('')
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Could not continue.', 'danger')
    } finally { setBusy(false) }
  }

  async function submitChannel() {
    const name = normalizeChannelName(channelName)
    if (!name) return
    setBusy(true)
    try {
      await createChannel(name, channelDescription.trim(), channelKind)
      setChannelDialog(false)
      setChannelName('')
      setChannelDescription('')
      setChannelKind('chat')
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Could not create channel.', 'danger')
    } finally { setBusy(false) }
  }

  const channelGroups = useMemo(() => {
    const channels = data?.channels ?? []
    return {
      announcements: channels.filter(channel => channel.kind === 'announcement'),
      conversations: channels.filter(channel => (channel.kind === 'chat' || channel.kind === 'mixed') && !/^(staff|mod|admin)[-_]/i.test(channel.name)),
      staff: canStaff ? channels.filter(channel => /^(staff|mod|admin)[-_]/i.test(channel.name)) : [],
      notes: channels.filter(channel => channel.kind === 'notes'),
    }
  }, [canStaff, data?.channels])

  return (
    <div className={`spaces-app-shell bg-${background} ${activeWorkspaceId ? 'has-space' : 'home-mode'} ${memberRailOpen && activeWorkspaceId ? 'with-member-rail' : ''}`} style={appStyle}>
      <aside className="server-rail">
        <button className={`server-home ${!activeWorkspaceId ? 'active' : ''}`} onClick={goHome} title="Spaces home"><div className="brand-mark brand-buildings"><SpacesLogo title="Spaces" /></div><span className="server-pill" /></button>
        <div className="server-divider" />
        <div className="server-list">
          {visibleWorkspaces.map(space => <button {...contextMenu.bind(space.name, workspaceActions(space), space.id === 'spaces-hub' ? 'Permanent Spaces Hub' : 'Space actions')} key={space.id} className={`server-button ${activeWorkspaceId === space.id ? 'active' : ''}`} onClick={() => void chooseWorkspace(space.id)} title={space.name} style={{ '--server-accent': space.accentColor, '--server-accent2': localStorage.getItem(`spaces.theme2.${space.id}`) || '#342044' } as CSSProperties}><span className="server-pill" /><span className={`server-avatar-shell space-icon-decor icon-decor-${space.iconDecoration ?? 'ring'}`} style={{ '--decor-accent': space.accentColor } as CSSProperties}><Avatar name={space.name} initials={space.initials} src={space.avatarUrl} size={46} accent={space.accentColor} /></span></button>)}
          <button className="server-button server-add" title="Add a Space" onClick={() => setSpaceDialog('create')}><Icon name="plus" size={20} /></button>
        </div>
      </aside>

      <aside className={`channel-sidebar ${mobileNavOpen ? 'mobile-open' : ''}`}>
        <header className="space-header">
          {activeWorkspace ? <><div className="space-header-copy"><span className="eyebrow">SPACE</span><strong>{activeWorkspace.name}</strong></div><button className="icon-button" title="Space settings" onClick={() => setView('settings')}><Icon name="settings" size={16} /></button></> : <><div className="space-header-copy"><span className="eyebrow">SPACES</span><strong>Home</strong></div><div className="private-chip"><Icon name="lock" size={12} /> Private</div></>}
        </header>

        <div className="sidebar-scroll">
          {!activeWorkspace ? (
            <>
              <div className="sidebar-section"><button className="sidebar-item active" onClick={goHome}><Icon name="home" /><span>Home</span></button><button className="sidebar-item" onClick={() => setCommandOpen(true)}><Icon name="search" /><span>Quick switcher</span><kbd>Ctrl K</kbd></button></div>
              <div className="sidebar-section"><div className="sidebar-section-label">YOUR SPACES</div>{visibleWorkspaces.map(space => <button {...contextMenu.bind(space.name, workspaceActions(space), 'Space actions')} className="sidebar-space-row" key={space.id} onClick={() => void chooseWorkspace(space.id)}><span className={`sidebar-space-avatar space-icon-decor icon-decor-${space.iconDecoration ?? 'ring'}`} style={{ '--decor-accent': space.accentColor } as CSSProperties}><Avatar name={space.name} initials={space.initials} src={space.avatarUrl} size={32} accent={space.accentColor} /></span><div><strong>{space.name}</strong><span>{space.role}</span></div><Icon name="chevron" size={14} /></button>)}</div>{canStaff && <div className="sidebar-section staff-sidebar-section"><div className="sidebar-section-label"><span>STAFF</span><Icon name="lock" size={11}/></div><button className={`sidebar-item ${view === 'staff' ? 'active' : ''}`} onClick={() => setView('staff')}><Icon name="shield" size={16}/><span>Staff</span></button><button className={`sidebar-item ${view === 'roles' ? 'active' : ''}`} onClick={() => setView('roles')}><Icon name="roles" size={16}/><span>Roles & Permissions</span></button></div>}
            </>
          ) : (
            <>
              <div className="mobile-space-strip" aria-label="Switch Space">
                <button className="mobile-space-home" title="Spaces home" onClick={goHome}><Icon name="home" size={15} /></button>
                {visibleWorkspaces.map(space => <button {...contextMenu.bind(space.name, workspaceActions(space), 'Hold for Space actions')} key={space.id} className={activeWorkspaceId === space.id ? 'active' : ''} title={space.name} onClick={() => void chooseWorkspace(space.id)}><span className={`space-icon-decor icon-decor-${space.iconDecoration ?? 'ring'}`} style={{ '--decor-accent': space.accentColor } as CSSProperties}><Avatar name={space.name} initials={space.initials} src={space.avatarUrl} size={34} accent={space.accentColor} /></span></button>)}
                <button className="mobile-space-add" title="New Space" onClick={() => setSpaceDialog('create')}><Icon name="plus" size={15} /></button>
              </div>
              <div className="sidebar-section">
                <button className={`sidebar-item ${view === 'home' ? 'active' : ''}`} onClick={() => setView('home')}><Icon name="home" /><span>Overview</span></button>
              </div>
              {channelGroups.announcements.length > 0 && <div className="sidebar-section"><div {...contextMenu.bind('Information', categoryActions('Information', channelGroups.announcements, 'announcement'), 'Right-click or hold for category actions')} className="sidebar-section-label context-enabled-label"><span>INFORMATION</span></div>{channelGroups.announcements.map(channel => <button {...contextMenu.bind(`#${channel.name}`, channelActions(channel), 'Channel actions')} key={channel.id} className={`sidebar-item channel-row ${activeChannel?.id === channel.id && view === 'chat' ? 'active' : ''} ${preferences.mutedChannelIds.includes(channel.id) ? 'muted' : ''}`} onClick={() => chooseChannel(channel.id)}><Icon name="bell" size={16}/><span>{channel.name}</span><small>{preferences.mutedChannelIds.includes(channel.id) ? 'MUTED' : 'NEWS'}</small></button>)}</div>}
              {channelGroups.conversations.length > 0 && <div className="sidebar-section">
                <div {...contextMenu.bind('Conversations', categoryActions('Conversations', channelGroups.conversations, 'chat'), 'Right-click or hold for category actions')} className="sidebar-section-label context-enabled-label"><span>CONVERSATIONS</span>{canCreateChannel && <button title="Create channel" onClick={() => setChannelDialog(true)}><Icon name="plus" size={13} /></button>}</div>
                {channelGroups.conversations.map(channel => <button {...contextMenu.bind(`#${channel.name}`, channelActions(channel), 'Right-click or hold for actions')} key={channel.id} className={`sidebar-item channel-row ${activeChannel?.id === channel.id && view === 'chat' ? 'active' : ''} ${preferences.mutedChannelIds.includes(channel.id) ? 'muted' : ''}`} onClick={() => chooseChannel(channel.id)}><Icon name={channel.kind === 'announcement' ? 'bell' : 'hash'} size={16} /><span>{channel.name}</span>{preferences.mutedChannelIds.includes(channel.id) && <small>MUTED</small>}</button>)}
              </div>}
              {channelGroups.notes.length > 0 && <div className="sidebar-section">
                <div {...contextMenu.bind('Notes', categoryActions('Notes', channelGroups.notes, 'notes'), 'Right-click or hold for category actions')} className="sidebar-section-label context-enabled-label"><span>NOTES</span>{canCreateChannel && <button title="Create channel" onClick={() => { setChannelKind('notes'); setChannelDialog(true) }}><Icon name="plus" size={13} /></button>}</div>
                {channelGroups.notes.map(channel => <button {...contextMenu.bind(channel.name, channelActions(channel), 'Note channel actions')} key={channel.id} className={`sidebar-item channel-row ${activeChannel?.id === channel.id && view === 'notes' ? 'active' : ''} ${preferences.mutedChannelIds.includes(channel.id) ? 'muted' : ''}`} onClick={() => chooseChannel(channel.id)}><Icon name="notes" size={16} /><span>{channel.name}</span>{preferences.mutedChannelIds.includes(channel.id) && <small>MUTED</small>}</button>)}
              </div>}
              {canStaff && channelGroups.staff.length > 0 && <div className="sidebar-section staff-channel-category"><div {...contextMenu.bind('Staff channels', categoryActions('Staff channels', channelGroups.staff, 'chat'), 'Right-click or hold for category actions')} className="sidebar-section-label context-enabled-label"><span>STAFF CHANNELS</span><Icon name="lock" size={11}/></div>{channelGroups.staff.map(channel => <button {...contextMenu.bind(`#${channel.name}`, channelActions(channel), 'Staff channel actions')} key={channel.id} className={`sidebar-item channel-row ${activeChannel?.id === channel.id && view === 'chat' ? 'active' : ''} ${preferences.mutedChannelIds.includes(channel.id) ? 'muted' : ''}`} onClick={() => chooseChannel(channel.id)}><Icon name="shield" size={16}/><span>{channel.name}</span>{preferences.mutedChannelIds.includes(channel.id) && <small>MUTED</small>}</button>)}</div>}
              <div className="sidebar-section sidebar-management"><div className="sidebar-section-label">SPACE</div>{navItems.filter(item => item.view !== 'invites' || canInvite).map(item => <button key={item.view} className={`sidebar-item ${view === item.view ? 'active' : ''}`} onClick={() => { setView(item.view); setMobileNavOpen(false) }}><Icon name={item.icon} size={16} /><span>{item.label}</span>{item.view === 'members' && <small>{data?.members.length ?? 0}</small>}</button>)}</div>
            </>
          )}
        </div>

        <footer className="account-dock">
          <button className="account-identity" onClick={() => setAccountMenuOpen(value => !value)} title="Account">
            <span className="account-avatar-wrap"><Avatar name={profile?.displayName} initials={profile?.initials} src={profile?.avatarUrl} size={36} /><i className={`status-dot status-${effectivePresence}`} /></span>
            <span><strong>{profile?.displayName}</strong><small>{preferences.customStatus ? `${preferences.customStatus}${profile?.platformRole ? ` · ${platformRoleLabel(profile.platformRole)}` : ''}` : `@${profile?.username}${profile?.platformRole ? ` · ${platformRoleLabel(profile.platformRole)}` : ''}`}</small></span>
          </button>
          <button className="icon-button" title="Account settings" onClick={() => { setAccountMenuOpen(false); setProfileDialog(true) }}><Icon name="settings" size={16} /></button>
        </footer>
        {accountMenuOpen && <><button className="account-menu-scrim" aria-label="Close account menu" onPointerDown={() => setAccountMenuOpen(false)} /><AccountQuickMenu onClose={() => setAccountMenuOpen(false)} onSettings={() => { setAccountMenuOpen(false); setProfileDialog(true) }} /></>}
      </aside>

      <main className="main-stage">
        <header className="topbar">
          <div className="topbar-left"><button className="mobile-menu-button" onClick={() => setMobileNavOpen(!mobileNavOpen)}><Icon name="menu" /></button>{activeWorkspace ? <><span className="topbar-symbol"><Icon name={view === 'notes' ? 'notes' : view === 'chat' ? 'hash' : navItems.find(item => item.view === view)?.icon ?? 'home'} size={18} /></span><div><strong>{view === 'chat' || view === 'notes' ? activeChannel?.name ?? activeWorkspace.name : navItems.find(item => item.view === view)?.label ?? 'Overview'}</strong><span>{activeChannel?.description || activeWorkspace.description || 'Spaces'}</span></div></> : <><span className="topbar-symbol"><Icon name="home" /></span><div><strong>Home</strong><span>Everything, one layer up.</span></div></>}</div>
          <div className="topbar-actions">
            <button className="search-pill" onClick={() => setCommandOpen(true)}><Icon name="search" size={15} /><span>Search Spaces</span><kbd>Ctrl K</kbd></button>
            <button className={`icon-button topbar-icon notification-button ${notificationOpen ? 'active' : ''}`} title="Notifications" onClick={() => setNotificationOpen(value => !value)}><Icon name="bell" size={17}/>{visibleNotifications.length > 0 && <i>{Math.min(99, visibleNotifications.length)}</i>}</button>
            {activeWorkspace && <button className={`icon-button topbar-icon ${memberRailOpen ? 'active' : ''}`} title="Toggle member rail" onClick={() => setMemberRailOpen(!memberRailOpen)}><Icon name="members" /></button>}
          </div>
        </header>

        <section className="view-host">
          {workspaceLoading ? <div className="loading-stage"><div className="spaces-loader"><i /><i /><i /></div><span>Opening Space…</span></div> : renderView(view, Boolean(activeWorkspaceId))}
        </section>
      </main>

      <nav className="mobile-homebar" aria-label="Spaces navigation">
        <button className={!activeWorkspaceId ? 'active' : ''} onClick={goHome}><Icon name="home" size={19} /><span>Home</span></button>
        <button className={mobileNavOpen || Boolean(activeWorkspaceId) ? 'active' : ''} onClick={() => setMobileNavOpen(!mobileNavOpen)}><Icon name="grid" size={19} /><span>Spaces</span></button>
        <button className={profileDialog ? 'active' : ''} onClick={() => setProfileDialog(true)}><Icon name="settings" size={19} /><span>Settings</span></button>
      </nav>

      {activeWorkspaceId && memberRailOpen && <MemberRail onOpenMember={setSelectedRailMember} />}
      {mobileNavOpen && <div className="mobile-scrim" onPointerDown={() => setMobileNavOpen(false)} />}
      {commandOpen && <CommandPalette />}
      <NotificationCenter open={notificationOpen} onClose={() => setNotificationOpen(false)} />
      {noticePeek && <IncomingNotificationPeek item={noticePeek} onOpen={() => void openNotificationItem(noticePeek)} onClose={() => setNoticePeek(null)} />}
      <div className="toast-stack">{toasts.map(toast => <div key={toast.id} className={`toast toast-${toast.tone}`}><span /><p>{toast.message}</p></div>)}</div>

      {profileDialog && <PersonalSettings onClose={() => setProfileDialog(false)} />}
      {selectedRailMember && <RailMemberProfile memberId={selectedRailMember} onClose={() => setSelectedRailMember(null)} />}

      {spaceDialog && <Modal title={spaceDialog === 'create' ? 'Create a Space' : 'Join a Space'} subtitle={spaceDialog === 'create' ? 'A new home for a project, team or group.' : 'Enter a Space or invite code.'} onClose={() => setSpaceDialog(null)}><label className="field-label">{spaceDialog === 'create' ? 'Space name' : 'Code'}<input className="text-input" autoFocus value={spaceValue} onChange={e => setSpaceValue(e.target.value)} onKeyDown={e => e.key === 'Enter' && void submitSpace()} /></label><div className="modal-actions"><button className="secondary-button" onClick={() => setSpaceDialog(null)}>Cancel</button><button className="primary-button" disabled={busy || !spaceValue.trim()} onClick={() => void submitSpace()}>{busy ? 'Working…' : spaceDialog === 'create' ? 'Create' : 'Join'}</button></div></Modal>}

      {channelDialog && <Modal title="Create channel" subtitle="Channels keep conversation and knowledge organized." onClose={() => setChannelDialog(false)}><label className="field-label">Channel name<input className="text-input" autoFocus value={channelName} onChange={e => setChannelName(e.target.value)} placeholder="design-room" /></label><label className="field-label">Description<input className="text-input" value={channelDescription} onChange={e => setChannelDescription(e.target.value)} placeholder="What belongs here?" /></label><div className="segmented-control">{(['chat', 'notes', 'mixed', 'announcement'] as const).map(kind => <button className={channelKind === kind ? 'active' : ''} key={kind} onClick={() => setChannelKind(kind)}>{kind}</button>)}</div><div className="modal-actions"><button className="secondary-button" onClick={() => setChannelDialog(false)}>Cancel</button><button className="primary-button" disabled={busy || !normalizeChannelName(channelName)} onClick={() => void submitChannel()}>{busy ? 'Creating…' : 'Create channel'}</button></div></Modal>}

      <ContextMenu menu={contextMenu.menu} onClose={contextMenu.close} />
      {channelPermissionTarget && <ChannelPermissionsEditor channel={channelPermissionTarget} onClose={() => setChannelPermissionTarget(null)} />}
    </div>
  )
}


function IncomingNotificationPeek({ item, onOpen, onClose }: { item: SpacesNotification; onOpen: () => void; onClose: () => void }) {
  return <aside className="incoming-notice page-enter" role="status">
    <button className="incoming-notice-main" onClick={onOpen}><span className="incoming-notice-icon notification-spaces-mark"><SpacesLogo title="Spaces ping" /></span><span><small>{item.workspaceName}</small><strong>{item.kind === 'everyone' ? `${item.authorName} pinged @everyone` : item.kind === 'here' ? `${item.authorName} pinged @here` : item.kind === 'role' ? `${item.authorName} pinged ${item.mentionLabel}` : item.kind === 'mention' ? `${item.authorName} mentioned you` : item.authorName}</strong><p>{item.preview}</p></span></button>
    <button className="incoming-notice-close" onClick={onClose} aria-label="Dismiss"><Icon name="x" size={13}/></button>
  </aside>
}

function MemberRail({ onOpenMember }: { onOpenMember: (memberId: string) => void }) {
  const { data } = useSpaces()
  const members = useMemo(() => [...(data?.members ?? [])].sort((a, b) => a.displayName.localeCompare(b.displayName)), [data?.members])
  const roles = [...(data?.roles ?? [])].sort((a,b) => b.position-a.position)
  const hoisted = roles.filter(role => role.hoist)
  const claimed = new Set<string>()
  const ownerMembers = members.filter(member => member.role === 'owner')
  ownerMembers.forEach(member => claimed.add(member.id))
  const adminMembers = members.filter(member => member.role === 'admin' && !claimed.has(member.id))
  adminMembers.forEach(member => claimed.add(member.id))
  const roleGroups = hoisted.map(role => { const grouped = members.filter(member => member.customRoleIds.includes(role.id) && !claimed.has(member.id)); grouped.forEach(member => claimed.add(member.id)); return { role, members: grouped } }).filter(group => group.members.length)
  const remaining = members.filter(member => !claimed.has(member.id))
  const online = remaining.filter(member => member.status !== 'offline')
  const offline = remaining.filter(member => member.status === 'offline')
  return <aside className="member-rail"><header><span className="eyebrow">PEOPLE</span><strong>{members.length} members</strong></header><div className="member-rail-scroll">{ownerMembers.length > 0 && <MemberRailGroup title="OWNER" members={ownerMembers} roles={roles} onOpenMember={onOpenMember} />}{adminMembers.length > 0 && <MemberRailGroup title="ADMINISTRATORS" members={adminMembers} roles={roles} onOpenMember={onOpenMember} />}{roleGroups.map(group => <MemberRailGroup key={group.role.id} title={group.role.name.toUpperCase()} members={group.members} roles={roles} onOpenMember={onOpenMember} />)}{online.length > 0 && <MemberRailGroup title="ONLINE" members={online} roles={roles} onOpenMember={onOpenMember} />}{offline.length > 0 && <MemberRailGroup title="OFFLINE" members={offline} roles={roles} onOpenMember={onOpenMember} />}</div></aside>
}

function MemberRailGroup({ title, members, roles, onOpenMember }: { title: string; members: NonNullable<ReturnType<typeof useSpaces>['data']>['members']; roles: NonNullable<ReturnType<typeof useSpaces>['data']>['roles']; onOpenMember: (memberId: string) => void }) {
  const { profile } = useSpaces()
  const { effectivePresence } = usePreferences()
  return <section className="member-rail-group"><div className="member-rail-label">{title} — {members.length}</div>{members.map(member => { const topRole = roles.filter(role => member.customRoleIds.includes(role.id)).sort((a, b) => b.position - a.position)[0]; const status = member.profileId === profile?.id ? effectivePresence : member.status === 'away' ? 'idle' : member.status; return <button className="member-rail-row" key={member.id} onClick={() => onOpenMember(member.id)}><div className="avatar-wrap"><Avatar name={member.displayName} initials={member.initials} src={member.avatarUrl} size={32} accent={topRole?.color} /><span className={`status-dot status-${status}`} /></div><div><strong style={topRole ? { color: topRole.color } : undefined}>{member.displayName}</strong><span>{member.platformRole ? platformRoleLabel(member.platformRole) : (topRole?.name ?? workspaceRoleLabel(member.role))}</span></div>{member.platformRole && <span className={`member-platform-rail platform-${member.platformRole}`}><Icon name="shield" size={12}/>{platformRoleLabel(member.platformRole)}</span>}</button> })}</section>
}

function AccountQuickMenu({ onClose, onSettings }: { onClose: () => void; onSettings: () => void }) {
  const { profile } = useSpaces()
  const { preferences, effectivePresence, setPreference } = usePreferences()
  const statusOptions = [
    { id: 'online' as const, label: 'Online', note: 'You appear online' },
    { id: 'idle' as const, label: 'Idle', note: 'You appear away' },
    { id: 'dnd' as const, label: 'Do Not Disturb', note: 'Suppress notifications' },
    { id: 'offline' as const, label: 'Invisible', note: 'You appear offline' },
  ]
  return <div className="account-quick-menu page-enter">
    <div className="account-quick-head"><div className="account-quick-avatar"><Avatar name={profile?.displayName} initials={profile?.initials} src={profile?.avatarUrl} size={48} accent={profile?.profileAccent}/><span className={`presence-symbol presence-${effectivePresence}`} /></div><div><strong>{profile?.displayName}</strong><span>@{profile?.username}</span></div><button className="icon-button" onClick={onClose}><Icon name="x" size={15}/></button></div>
    <label className="quick-status-input"><span>STATUS <small>{preferences.customStatus.length}/128</small></span><input value={preferences.customStatus} maxLength={128} onChange={event => setPreference('customStatus', event.target.value)} placeholder="Set a custom status…" /></label>
    <div className="quick-presence-list">{statusOptions.map(option => <button key={option.id} className={preferences.presence === option.id ? 'active' : ''} onClick={() => setPreference('presence', option.id)}><span className={`presence-symbol presence-${option.id}`} /><div><strong>{option.label}</strong><span>{option.note}</span></div>{preferences.presence === option.id && <Icon name="check" size={14}/>}</button>)}</div>
    <button className="quick-settings-button" onClick={onSettings}><Icon name="settings" size={15}/><span>Account settings</span><Icon name="chevron" size={13}/></button>
  </div>
}

function CommandPalette() {
  const { profile, workspaces, data, activeWorkspaceId, chooseWorkspace, chooseChannel, setView, setCommandOpen } = useSpaces()
  const { preferences } = usePreferences()
  const visibleWorkspaces = workspaces.filter(space => !preferences.hiddenWorkspaceIds.includes(space.id))
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(0)
  const q = query.trim().toLowerCase()
  const canInvite = hasWorkspacePermission(data, profile?.id, 'create_invites')
  const commands = [
    ...visibleWorkspaces.map(space => ({ key: `space-${space.id}`, label: space.name, meta: 'Space', icon: 'grid' as IconName, run: () => void chooseWorkspace(space.id) })),
    ...(data?.channels ?? []).map(channel => ({ key: `channel-${channel.id}`, label: `# ${channel.name}`, meta: channel.kind, icon: channel.kind === 'notes' ? 'notes' as IconName : 'hash' as IconName, run: () => chooseChannel(channel.id) })),
    ...(data?.notes ?? []).map(note => ({ key: `note-${note.id}`, label: note.title, meta: 'Note', icon: 'notes' as IconName, run: () => chooseChannel(note.channelId) })),
    ...(data?.members ?? []).map(member => ({ key: `member-${member.id}`, label: `@${member.username}`, meta: member.displayName, icon: 'user' as IconName, run: () => setView('members') })),
    ...(activeWorkspaceId ? navItems.filter(item => item.view !== 'invites' || canInvite).map(item => ({ key: `view-${item.view}`, label: item.label, meta: 'View', icon: item.icon, run: () => setView(item.view) })) : []),
  ].filter(item => !q || `${item.label} ${item.meta}`.toLowerCase().includes(q)).slice(0, 14)

  function openSelected() {
    const item = commands[Math.min(selected, Math.max(0, commands.length - 1))]
    if (!item) return
    item.run()
    setCommandOpen(false)
  }

  return <div className="command-backdrop" onPointerDown={event => event.target === event.currentTarget && setCommandOpen(false)}><section className="command-palette"><div className="command-search"><Icon name="search" /><input autoFocus value={query} onChange={event => { setQuery(event.target.value); setSelected(0) }} onKeyDown={event => { if (event.key === 'ArrowDown') { event.preventDefault(); setSelected(value => commands.length ? (value + 1) % commands.length : 0) } else if (event.key === 'ArrowUp') { event.preventDefault(); setSelected(value => commands.length ? (value - 1 + commands.length) % commands.length : 0) } else if (event.key === 'Enter') { event.preventDefault(); openSelected() } }} placeholder="Jump to a Space, channel, member…" /><kbd>ESC</kbd></div><div className="command-results">{commands.map((item, index) => <button className={selected === index ? 'selected' : ''} key={item.key} onMouseEnter={() => setSelected(index)} onClick={() => { item.run(); setCommandOpen(false) }}><span className="command-icon"><Icon name={item.icon} size={16} /></span><div><strong>{item.label}</strong><span>{item.meta}</span></div>{selected === index && <kbd>↵</kbd>}</button>)}{!commands.length && <div className="command-empty">No results for “{query}”.</div>}</div><footer><span><kbd>↑</kbd><kbd>↓</kbd> Navigate</span><span><kbd>Enter</kbd> Open</span><span><kbd>Esc</kbd> Close</span></footer></section></div>
}

function RailMemberProfile({ memberId, onClose }: { memberId: string; onClose: () => void }) {
  const { data, profile, reportUser, pushToast } = useSpaces()
  const { preferences, effectivePresence } = usePreferences()
  const member = data?.members.find(item => item.id === memberId)
  const roles = (data?.roles ?? []).filter(role => member?.customRoleIds.includes(role.id)).sort((a,b) => b.position-a.position)
  if (!member) return null
  const status = member.profileId === profile?.id ? effectivePresence : member.status === 'away' ? 'idle' : member.status
  const statusLabel = status === 'dnd' ? 'Do Not Disturb' : status === 'offline' ? 'Offline' : status === 'idle' ? 'Idle' : 'Online'
  const customStatus = member.profileId === profile?.id ? preferences.customStatus.trim() : ''
  return <Modal title={member.displayName} subtitle={`@${member.username}`} onClose={onClose}>
    <div className="rail-profile-card">
      <div className="rail-profile-banner" style={member.bannerUrl ? { backgroundImage: `linear-gradient(to bottom, transparent, rgba(8,8,12,.78)), url(${member.bannerUrl})`, backgroundSize: 'cover', backgroundPosition: 'center' } : { background: `linear-gradient(135deg, ${member.profileAccent || '#8b6ca8'}33, rgba(255,255,255,.02))` }}/>
      <div className="rail-profile-avatar"><Avatar name={member.displayName} initials={member.initials} src={member.avatarUrl} size={76} accent={roles[0]?.color}/><span className={`presence-symbol presence-${status}`}/></div>
      <div className="rail-profile-copy">
        <div className="rail-profile-name-row"><h3>{member.displayName}</h3><span className={`member-profile-status presence-text presence-text-${status}`}>{statusLabel}</span></div>
        <span className="rail-profile-handle">@{member.username}</span>
        {customStatus && <p className="rail-profile-custom-status">{customStatus}</p>}
        {member.bio && <p className="rail-profile-custom-status rail-profile-bio">{member.bio}</p>}
        {member.platformRole && <span className={`founder-badge rail-platform-badge platform-${member.platformRole}`}><Icon name="shield" size={12}/>{platformRoleLabel(member.platformRole)}</span>}
        <details className="rail-profile-roles profile-submenu" open><summary><span><Icon name="roles" size={13}/><strong>Roles</strong></span><span>{1 + roles.length + (member.platformRole ? 1 : 0)}</span></summary><div className="rail-role-chips">{member.platformRole && <i className={`platform-role-chip platform-${member.platformRole}`}>{platformRoleLabel(member.platformRole)}</i>}<i className={`base-role-chip role-${member.role}`}>{workspaceRoleLabel(member.role)}</i>{roles.map(role => <i key={role.id} style={{color:role.color,borderColor:role.color}}>{role.name}</i>)}</div></details>
      </div>
      <div className="modal-actions"><button className="secondary-button" onClick={() => pushToast('Direct Messages are next in the messaging backend pass.', 'info')}><Icon name="chat" size={14}/> Message</button>{member.profileId !== profile?.id && <button className="secondary-button" onClick={() => { const reason=window.prompt('Reason for report?')?.trim(); if(reason) void reportUser(member.profileId, reason, '') }}><Icon name="shield" size={14}/> Report</button>}</div>
    </div>
  </Modal>
}
