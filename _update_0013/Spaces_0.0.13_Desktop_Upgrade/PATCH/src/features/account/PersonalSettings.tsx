import { useEffect, useMemo, useRef, useState, type ChangeEvent, type CSSProperties } from 'react'
import { Avatar } from '../../components/Avatar'
import { Icon, type IconName } from '../../components/Icon'
import { Modal } from '../../components/Modal'
import { ImageCropper } from '../../components/ImageCropper'
import { usePreferences, type ContentFilterLevel, type MessageDensity, type NotificationLevel, type AppTheme } from '../../state/PreferencesContext'
import { useSpaces } from '../../state/SpacesContext'
import type { WorkspaceSessionInfo } from '../../types/spaces'
import { contentFilterExample } from '../../utils/content-filter'
import { imageFileToRawDataUrl } from '../../utils/image'
import { formatTime } from '../../utils/format'
import { platformRoleLabel } from '../../utils/permissions'

type Tab = 'profile' | 'content' | 'appearance' | 'notifications' | 'security'

const tabs: { id: Tab; label: string; icon: IconName }[] = [
  { id: 'profile', label: 'My Profile', icon: 'user' },
  { id: 'content', label: 'Content & Safety', icon: 'shield' },
  { id: 'appearance', label: 'Appearance', icon: 'sparkle' },
  { id: 'notifications', label: 'Notifications', icon: 'bell' },
  { id: 'security', label: 'Security', icon: 'lock' },
]

export function PersonalSettings({ onClose }: { onClose: () => void }) {
  const {
    profile, workspaces, updateProfile, setAvatar, setBanner, listSessions, revokeSession,
    changePassword, logout, pushToast,
  } = useSpaces()
  const { preferences, setPreference, resetPreferences } = usePreferences()
  const [tab, setTab] = useState<Tab>('profile')
  const [displayName, setDisplayName] = useState(profile?.displayName ?? '')
  const [bio, setBio] = useState(profile?.bio ?? '')
  const [publicProfile, setPublicProfile] = useState(profile?.publicProfile ?? true)
  const [profileAccent, setProfileAccent] = useState(profile?.profileAccent ?? '#8b6ca8')
  const [busy, setBusy] = useState(false)
  const [sessions, setSessions] = useState<WorkspaceSessionInfo[]>([])
  const [sessionsLoading, setSessionsLoading] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [cropTarget, setCropTarget] = useState<{ kind: 'avatar' | 'banner'; source: string } | null>(null)
  const avatarInput = useRef<HTMLInputElement>(null)
  const bannerInput = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!profile) return
    setDisplayName(profile.displayName)
    setBio(profile.bio)
    setPublicProfile(profile.publicProfile)
    setProfileAccent(profile.profileAccent || '#8b6ca8')
  }, [profile])

  useEffect(() => {
    if (tab !== 'security') return
    setSessionsLoading(true)
    void listSessions()
      .then(setSessions)
      .catch(error => pushToast(error instanceof Error ? error.message : 'Could not load sessions.', 'danger'))
      .finally(() => setSessionsLoading(false))
  }, [listSessions, pushToast, tab])

  const moderationLevels = useMemo(() => (['none', 'low', 'medium', 'high'] as ContentFilterLevel[]), [])
  const profileDirty = Boolean(profile && (
    displayName !== profile.displayName ||
    bio !== profile.bio ||
    publicProfile !== profile.publicProfile ||
    profileAccent !== (profile.profileAccent || '#8b6ca8')
  ))
  function resetProfileDraft() {
    if (!profile) return
    setDisplayName(profile.displayName)
    setBio(profile.bio)
    setPublicProfile(profile.publicProfile)
    setProfileAccent(profile.profileAccent || '#8b6ca8')
  }

  async function saveProfile() {
    if (!displayName.trim() || busy) return
    setBusy(true)
    try {
      await updateProfile({
        displayName: displayName.trim(),
        bio: bio.slice(0, 240),
        publicProfile,
        profileAccent,
      })
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Could not save profile.', 'danger')
    } finally {
      setBusy(false)
    }
  }

  async function uploadImage(event: ChangeEvent<HTMLInputElement>, kind: 'avatar' | 'banner') {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    try {
      const source = await imageFileToRawDataUrl(file)
      setCropTarget({ kind, source })
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Could not upload image.', 'danger')
    }
  }

  function editCurrentImage(kind: 'avatar' | 'banner') {
    const current = kind === 'avatar' ? profile?.avatarUrl : profile?.bannerUrl
    if (current?.startsWith('data:image/')) setCropTarget({ kind, source: current })
    else if (kind === 'avatar') avatarInput.current?.click()
    else bannerInput.current?.click()
  }

  async function submitPassword() {
    if (!currentPassword || newPassword.length < 8) return
    setBusy(true)
    try {
      await changePassword(currentPassword, newPassword)
      setCurrentPassword('')
      setNewPassword('')
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Could not change password.', 'danger')
    } finally {
      setBusy(false)
    }
  }

  async function removeSession(id: string) {
    try {
      await revokeSession(id)
      setSessions(current => current.filter(item => item.id !== id))
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Could not revoke session.', 'danger')
    }
  }

  return (
    <Modal title="Settings" subtitle="Your account, safety and Spaces experience." onClose={onClose} wide>
      <div className="personal-settings-shell">
        <nav className="personal-settings-nav">
          <div className="settings-profile-mini">
            <Avatar name={profile?.displayName} initials={profile?.initials} src={profile?.avatarUrl} size={40} accent={profileAccent} />
            <div><strong>{profile?.displayName}</strong><span>@{profile?.username}</span></div>
          </div>
          {tabs.map(item => <button key={item.id} className={tab === item.id ? 'active' : ''} onClick={() => setTab(item.id)}><Icon name={item.icon} size={16} /><span>{item.label}</span></button>)}
          <div className="settings-nav-spacer" />
          <button className="settings-signout" onClick={() => void logout()}><Icon name="logout" size={16} /><span>Sign out</span></button>
        </nav>

        <section className="personal-settings-content">
          {tab === 'profile' && <>
            <div className="settings-page-heading"><span className="eyebrow">IDENTITY</span><h2>My Profile</h2><p>How you appear across Spaces.</p></div>
            <div className="profile-editor-preview" style={{ '--profile-accent': profileAccent } as CSSProperties}>
              <div className="profile-editor-banner" style={profile?.bannerUrl ? { backgroundImage: `linear-gradient(to bottom, transparent, rgba(8,8,12,.68)), url(${profile.bannerUrl})` } : undefined}>
                <button className="image-upload-button" disabled={busy} onClick={() => editCurrentImage('banner')}><Icon name="edit" size={14} /> Change banner</button>
              </div>
              <div className="profile-editor-identity">
                <button className="profile-avatar-edit" disabled={busy} onClick={() => editCurrentImage('avatar')}>
                  <Avatar name={profile?.displayName} initials={profile?.initials} src={profile?.avatarUrl} size={76} accent={profileAccent} />
                  <span><Icon name="edit" size={14} /></span>
                </button>
                <div><h3>{displayName || profile?.displayName}</h3><p>@{profile?.username}</p></div>
                {profile?.platformRole && <span className={`founder-badge platform-${profile.platformRole}`}><Icon name="shield" size={13} /> {platformRoleLabel(profile.platformRole)}</span>}
              </div>
            </div>
            <input ref={avatarInput} hidden type="file" accept="image/png,image/jpeg,image/webp" onChange={event => void uploadImage(event, 'avatar')} />
            <input ref={bannerInput} hidden type="file" accept="image/png,image/jpeg,image/webp" onChange={event => void uploadImage(event, 'banner')} />
            {cropTarget && <ImageCropper source={cropTarget.source} preset={cropTarget.kind} title={cropTarget.kind === 'avatar' ? 'Edit profile photo' : 'Adjust profile banner'} onCancel={() => setCropTarget(null)} onSave={async dataUrl => { setBusy(true); try { if (cropTarget.kind === 'avatar') await setAvatar(dataUrl); else await setBanner(dataUrl); setCropTarget(null) } finally { setBusy(false) } }} />}

            <div className="settings-form-grid">
              <label className="field-label">Display name<input className="text-input" value={displayName} maxLength={40} onChange={event => setDisplayName(event.target.value)} /></label>
              <label className="field-label">Profile accent<div className="accent-field account-accent"><input type="color" value={profileAccent} onChange={event => setProfileAccent(event.target.value)} /><code>{profileAccent}</code></div></label>
              <label className="field-label span-2">About me<textarea className="text-area" rows={4} maxLength={240} value={bio} onChange={event => setBio(event.target.value)} /><small>{bio.length}/240</small></label>
            </div>
            <ToggleRow title="Public profile" description="Allow other Spaces members to open your public profile." checked={publicProfile} onChange={setPublicProfile} />
            <div className="settings-action-row"><button className="secondary-button" disabled={busy || !profile?.avatarUrl} onClick={() => void setAvatar(null)}>Remove photo</button><button className="secondary-button" disabled={busy || !profile?.bannerUrl} onClick={() => void setBanner(null)}>Remove banner</button></div>{profileDirty && <div className="profile-save-bar unsaved-bar"><span><strong>You have unsaved profile changes.</strong><small>Review them before leaving this page.</small></span><div><button className="secondary-button compact" disabled={busy} onClick={resetProfileDraft}>Reset</button><button className="primary-button" disabled={busy || !displayName.trim()} onClick={() => void saveProfile()}>{busy ? 'Saving…' : 'Save changes'}</button></div></div>}
          </>}

          {tab === 'content' && <>
            <div className="settings-page-heading"><span className="eyebrow">PERSONAL MODERATION</span><h2>Content & Safety</h2><p>Control how strong language is displayed to you. Messages themselves are never changed.</p></div>
            <section className="moderation-card">
              <div className="moderation-card-head"><div><strong>Strong language filter</strong><span>Applied locally to chat, notes and comments.</span></div><div className="moderation-live-example"><span>You see</span><strong>{contentFilterExample(preferences.contentFilter)}</strong></div></div>
              <div className="moderation-levels">
                {moderationLevels.map(level => <button key={level} className={preferences.contentFilter === level ? 'active' : ''} onClick={() => setPreference('contentFilter', level)}><span>{level}</span><strong>{contentFilterExample(level)}</strong>{preferences.contentFilter === level && <Icon name="check" size={14} />}</button>)}
              </div>
              <p className="settings-footnote">Choose how strongly recognized language is masked on this device. Original messages are never changed.</p>
            </section>
          </>}

          {tab === 'appearance' && <>
            <div className="settings-page-heading"><span className="eyebrow">DISPLAY</span><h2>Appearance</h2><p>Tune Spaces for desktop or a smaller phone screen.</p></div>
            <ChoiceRow title="App theme" description="Choose your personal Spaces atmosphere." value={preferences.appTheme} options={[['obsidian', 'Obsidian'], ['midnight', 'Midnight'], ['slate', 'Slate'], ['soft', 'Soft Glass']] as [AppTheme, string][]} onChange={value => setPreference('appTheme', value as AppTheme)} />
            <div className="setting-row personal-setting-row accent-preference-row">
              <div><strong>Accent color</strong><span>Spaces stays black; this changes the personal accent used across buttons, focus states, highlights and motion.</span></div>
              <div className="personal-accent-picker">
                <input aria-label="Accent color" type="color" value={preferences.appAccent} onChange={event => setPreference('appAccent', event.target.value)} />
                <code>{preferences.appAccent}</code>
                <div className="accent-swatches">
                  {['#8b6ca8','#d57b45','#4f8d78','#5f79b6','#b95d76','#c19b52'].map(color => <button key={color} aria-label={`Use ${color}`} className={preferences.appAccent === color ? 'active' : ''} style={{ background: color }} onClick={() => setPreference('appAccent', color)} />)}
                </div>
              </div>
            </div>
            <ChoiceRow title="Message density" description="Comfortable gives conversations more breathing room." value={preferences.messageDensity} options={[['comfortable', 'Comfortable'], ['compact', 'Compact']]} onChange={value => setPreference('messageDensity', value as MessageDensity)} />
            <ToggleRow title="Glass effects" description="Blurred translucent surfaces and layered depth." checked={preferences.glassEffects} onChange={value => setPreference('glassEffects', value)} />
            <ToggleRow title="Reduced motion" description="Cuts boot, panel, hover and message movement." checked={preferences.reducedMotion} onChange={value => setPreference('reducedMotion', value)} />
            <ToggleRow title="Spaces cursor" description="Use the subtle Spaces crosshair cursor on desktop. Touch devices always use native input." checked={preferences.customCursor} onChange={value => setPreference('customCursor', value)} />
            <ToggleRow title="Enter to send" description="Press Enter to send, Shift+Enter for a new line." checked={preferences.enterToSend} onChange={value => setPreference('enterToSend', value)} />
            <button className="secondary-button settings-reset" onClick={resetPreferences}>Reset personal appearance</button>
          </>}

          {tab === 'notifications' && <>
            <div className="settings-page-heading"><span className="eyebrow">ATTENTION</span><h2>Notifications</h2><p>Spaces-drawn alerts and ping controls for this device. No browser hostname notifications.</p></div>
            <ChoiceRow title="Message notifications" description="Choose how noisy Spaces is on this device." value={preferences.notificationLevel} options={[['all', 'All messages'], ['mentions', 'Mentions only'], ['none', 'Nothing']]} onChange={value => setPreference('notificationLevel', value as NotificationLevel)} />
            <ToggleRow title="Notification sounds" description="Play a subtle sound with Spaces in-app alerts and pings." checked={preferences.desktopSounds} onChange={value => setPreference('desktopSounds', value)} />
            <section className="space-notification-controls">
              <div className="section-heading"><div><span className="eyebrow">SPACES</span><h3>Per-Space controls</h3><p>Mute noisy Spaces or hide them from your rails without leaving.</p></div></div>
              <div className="space-preference-list">
                {workspaces.map(space => {
                  const muted = preferences.mutedWorkspaceIds.includes(space.id)
                  const hidden = preferences.hiddenWorkspaceIds.includes(space.id)
                  const permanent = space.id === 'spaces-hub'
                  return <div className="space-preference-row" key={space.id}>
                    <Avatar name={space.name} initials={space.initials} src={space.avatarUrl} size={34} accent={space.accentColor} />
                    <div><strong>{space.name}</strong><span>{permanent ? 'Permanent platform Space' : 'Your Space'}</span></div>
                    <button className={`mini-toggle ${muted ? 'active' : ''}`} onClick={() => setPreference('mutedWorkspaceIds', muted ? preferences.mutedWorkspaceIds.filter(id => id !== space.id) : [...preferences.mutedWorkspaceIds, space.id])}><Icon name={muted ? 'bell' : 'bell'} size={13}/>{muted ? 'Muted' : 'Mute'}</button>
                    <button className={`mini-toggle ${hidden ? 'active' : ''}`} onClick={() => setPreference('hiddenWorkspaceIds', hidden ? preferences.hiddenWorkspaceIds.filter(id => id !== space.id) : [...preferences.hiddenWorkspaceIds, space.id])}>{hidden ? 'Unhide' : 'Hide'}</button>
                  </div>
                })}
              </div>
            </section>
          </>}

          {tab === 'security' && <>
            <div className="settings-page-heading"><span className="eyebrow">ACCOUNT SECURITY</span><h2>Password & Sessions</h2><p>Control where your private-beta account is signed in.</p></div>
            <section className="settings-card settings-card-stack security-card">
              <label className="field-label">Current password<input className="text-input" type="password" value={currentPassword} onChange={event => setCurrentPassword(event.target.value)} /></label>
              <label className="field-label">New password<input className="text-input" type="password" value={newPassword} minLength={8} onChange={event => setNewPassword(event.target.value)} placeholder="8+ characters" /></label>
              <div className="settings-action-row"><button className="primary-button" disabled={busy || !currentPassword || newPassword.length < 8} onClick={() => void submitPassword()}>Change password</button></div>
            </section>
            <section className="sessions-section">
              <div className="section-heading"><div><span className="eyebrow">SIGNED IN</span><h3>Sessions</h3></div><button className="icon-button" title="Refresh" onClick={() => { setSessionsLoading(true); void listSessions().then(setSessions).finally(() => setSessionsLoading(false)) }}><Icon name="refresh" size={15} /></button></div>
              {sessionsLoading ? <div className="settings-loading">Loading sessions…</div> : <div className="session-list">{sessions.map(item => <div className="session-row" key={item.id}><span className={`session-pip ${item.current ? 'current' : ''}`} /><div><strong>{item.current ? 'This device' : 'Spaces session'}</strong><span>Last active {formatTime(item.lastSeenAt)}</span></div>{!item.current && <button className="ghost-danger" onClick={() => void removeSession(item.id)}>Revoke</button>}</div>)}{!sessions.length && <p className="settings-footnote">No sessions returned.</p>}</div>}
            </section>
          </>}
        </section>
      </div>
    </Modal>
  )
}

function ToggleRow({ title, description, checked, onChange }: { title: string; description: string; checked: boolean; onChange: (checked: boolean) => void }) {
  return <div className="setting-row personal-setting-row"><div><strong>{title}</strong><span>{description}</span></div><button type="button" className={`switch ${checked ? 'on' : ''}`} onClick={() => onChange(!checked)} aria-pressed={checked}><i /></button></div>
}

function ChoiceRow({ title, description, value, options, onChange }: { title: string; description: string; value: string; options: [string, string][]; onChange: (value: string) => void }) {
  return <div className="setting-row personal-setting-row align-start"><div><strong>{title}</strong><span>{description}</span></div><div className="choice-pills">{options.map(([id, label]) => <button key={id} className={value === id ? 'active' : ''} onClick={() => onChange(id)}>{label}</button>)}</div></div>
}
