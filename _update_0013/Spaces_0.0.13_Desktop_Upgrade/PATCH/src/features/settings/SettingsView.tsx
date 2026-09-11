import { useEffect, useRef, useState, type ChangeEvent, type CSSProperties } from 'react'
import { Avatar } from '../../components/Avatar'
import { Icon } from '../../components/Icon'
import { ImageCropper } from '../../components/ImageCropper'
import { ChannelPermissionsEditor } from '../../components/ChannelPermissionsEditor'
import { useSpaces } from '../../state/SpacesContext'
import { hasWorkspacePermission } from '../../utils/permissions'
import { imageFileToRawDataUrl } from '../../utils/image'
import type { WorkspaceBackgroundPreset, WorkspaceChannel, WorkspaceIconDecoration } from '../../types/spaces'

const iconDecorations: { id: WorkspaceIconDecoration; label: string }[] = [
  { id: 'none', label: 'None' }, { id: 'ring', label: 'Ring' },
  { id: 'double', label: 'Double' }, { id: 'halo', label: 'Halo' },
  { id: 'badge', label: 'Badge' },
]

const backgrounds: { id: WorkspaceBackgroundPreset; label: string }[] = [
  { id: 'graphite', label: 'Graphite' }, { id: 'midnight', label: 'Midnight' },
  { id: 'slate', label: 'Slate' }, { id: 'black', label: 'Black' },
  { id: 'carbon', label: 'Carbon' }, { id: 'violet-grid', label: 'Violet Grid' },
  { id: 'deep-space', label: 'Deep Space' }, { id: 'glassline', label: 'Glassline' },
]

export function SettingsView() {
  const { data, profile, updateWorkspace, leaveWorkspace, deleteWorkspace, pushToast } = useSpaces()
  const workspace = data?.workspace
  const canManage = hasWorkspacePermission(data, profile?.id, 'manage_space')
  const isOwner = workspace?.role === 'owner'
  const isHub = workspace?.id === 'spaces-hub'
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [accent, setAccent] = useState('#8b6ca8')
  const [background, setBackground] = useState<WorkspaceBackgroundPreset>('graphite')
  const [accentTwo, setAccentTwo] = useState(() => localStorage.getItem(`spaces.theme2.${workspace?.id ?? 'preview'}`) || '#342044')
  const [avatarUrl, setAvatarUrl] = useState<string | null>(null)
  const [bannerUrl, setBannerUrl] = useState<string | null>(null)
  const [iconDecoration, setIconDecoration] = useState<WorkspaceIconDecoration>('ring')
  const [busy, setBusy] = useState(false)
  const [cropTarget, setCropTarget] = useState<{ kind: 'avatar' | 'banner'; source: string } | null>(null)
  const [permissionChannel, setPermissionChannel] = useState<WorkspaceChannel | null>(null)
  const avatarInput = useRef<HTMLInputElement>(null)
  const bannerInput = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!workspace) return
    setName(workspace.name)
    setDescription(workspace.description)
    setAccent(workspace.accentColor)
    setBackground(workspace.background)
    setAccentTwo(localStorage.getItem(`spaces.theme2.${workspace.id}`) || '#342044')
    setAvatarUrl(workspace.avatarUrl)
    setBannerUrl(workspace.bannerUrl)
    setIconDecoration(workspace.iconDecoration ?? 'ring')
  }, [workspace])

  if (!workspace) return null

  const storedAccentTwo = localStorage.getItem(`spaces.theme2.${workspace.id}`) || '#342044'
  const dirty = canManage && (
    name !== workspace.name ||
    description !== workspace.description ||
    accent !== workspace.accentColor ||
    accentTwo !== storedAccentTwo ||
    background !== workspace.background ||
    avatarUrl !== workspace.avatarUrl ||
    bannerUrl !== workspace.bannerUrl ||
    iconDecoration !== (workspace.iconDecoration ?? 'ring')
  )

  function resetChanges() {
    if (!workspace) return
    setName(workspace.name)
    setDescription(workspace.description)
    setAccent(workspace.accentColor)
    setAccentTwo(storedAccentTwo)
    setBackground(workspace.background)
    setAvatarUrl(workspace.avatarUrl)
    setBannerUrl(workspace.bannerUrl)
    setIconDecoration(workspace.iconDecoration ?? 'ring')
    window.dispatchEvent(new CustomEvent('spaces-background-preview', { detail: workspace.background }))
  }

  async function uploadImage(event: ChangeEvent<HTMLInputElement>, kind: 'avatar' | 'banner') {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    try {
      const source = await imageFileToRawDataUrl(file)
      setCropTarget({ kind, source })
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Could not prepare that image.', 'danger')
    }
  }

  function editCurrentImage(kind: 'avatar' | 'banner') {
    const current = kind === 'avatar' ? avatarUrl : bannerUrl
    if (current?.startsWith('data:image/')) setCropTarget({ kind, source: current })
    else if (kind === 'avatar') avatarInput.current?.click()
    else bannerInput.current?.click()
  }

  async function save() {
    if (!workspace || !name.trim() || !canManage) return
    setBusy(true)
    try {
      localStorage.setItem(`spaces.theme2.${workspace.id}`, accentTwo)
      window.dispatchEvent(new CustomEvent('spaces-theme-updated'))
      await updateWorkspace({
        name: name.trim(),
        description: description.trim(),
        accentColor: accent,
        background,
        avatarUrl,
        bannerUrl,
        iconDecoration,
      })
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Could not update Space.', 'danger')
    } finally {
      setBusy(false)
    }
  }

  async function leave() {
    if (isHub) { pushToast('Spaces - Hub is permanent and cannot be left.', 'info'); return }
    if (isOwner) {
      pushToast('Owners must transfer ownership or delete the Space.', 'danger')
      return
    }
    if (!window.confirm(`Leave ${workspace?.name ?? 'this Space'}?`)) return
    try { await leaveWorkspace() } catch (error) { pushToast(error instanceof Error ? error.message : 'Could not leave Space.', 'danger') }
  }

  async function removeSpace() {
    if (isHub) { pushToast('Spaces - Hub is permanent and cannot be deleted.', 'info'); return }
    if (!isOwner || !window.confirm(`Permanently delete ${workspace?.name ?? 'this Space'}? This cannot be undone.`)) return
    const confirmation = window.prompt(`Type ${workspace?.name ?? 'the Space name'} to confirm deletion.`)
    if (!workspace || confirmation !== workspace.name) return
    try { await deleteWorkspace() } catch (error) { pushToast(error instanceof Error ? error.message : 'Could not delete Space.', 'danger') }
  }

  return (
    <div className="view-scroll settings-view page-enter">
      <div className="content-heading"><div><span className="eyebrow">SPACE MANAGEMENT</span><h1>Settings</h1><p>Identity, atmosphere, access and shared appearance.</p></div><Icon name="settings" size={26} /></div>

      <section className="space-profile-editor" style={{ '--space-profile-accent': accent } as CSSProperties}>
        <div className="space-profile-banner" style={bannerUrl ? { backgroundImage: `linear-gradient(to bottom, transparent, rgba(6,6,9,.74)), url(${bannerUrl})` } : undefined}>
          {canManage && <button className="image-upload-button" onClick={() => editCurrentImage('banner')}><Icon name="edit" size={14} /> {bannerUrl ? 'Adjust banner' : 'Add banner'}</button>}
        </div>
        <div className="space-profile-body">
          <button className="space-avatar-edit" disabled={!canManage} onClick={() => editCurrentImage('avatar')} title="Edit Space picture">
            <span className={`space-icon-decor icon-decor-${iconDecoration}`} style={{ '--decor-accent': accent, '--decor-accent-2': accentTwo } as CSSProperties}><Avatar name={name || workspace.name} initials={workspace.initials} src={avatarUrl} size={78} accent={accent} /></span>
            {canManage && <span><Icon name="edit" size={14} /></span>}
          </button>
          <div><span className="eyebrow">SPACE PROFILE</span><h2>{name || workspace.name}</h2><p>{description || 'Your shared home on Spaces.'}</p></div>
          <code className="space-code-chip">{workspace.code}</code>
        </div>
      </section>
      <input ref={avatarInput} hidden type="file" accept="image/png,image/jpeg,image/webp" onChange={event => void uploadImage(event, 'avatar')} />
      <input ref={bannerInput} hidden type="file" accept="image/png,image/jpeg,image/webp" onChange={event => void uploadImage(event, 'banner')} />
      {cropTarget && <ImageCropper source={cropTarget.source} preset={cropTarget.kind} title={cropTarget.kind === 'avatar' ? 'Edit Space picture' : 'Adjust Space banner'} onCancel={() => setCropTarget(null)} onSave={dataUrl => { if (cropTarget.kind === 'avatar') setAvatarUrl(dataUrl); else setBannerUrl(dataUrl); setCropTarget(null) }} />}
      {permissionChannel && <ChannelPermissionsEditor channel={permissionChannel} onClose={() => setPermissionChannel(null)} />}

      <section className="settings-card settings-card-stack">
        <div className="setting-row"><div><strong>Space name</strong><span>The name members see everywhere.</span></div><input className="text-input medium-input" disabled={!canManage} value={name} maxLength={48} onChange={e => setName(e.target.value)} /></div>
        <div className="setting-row align-start"><div><strong>Description</strong><span>Short context for what this Space is for.</span></div><textarea className="text-area medium-input" disabled={!canManage} value={description} maxLength={220} onChange={e => setDescription(e.target.value)} rows={4} /></div>
        <div className="setting-row align-start"><div><strong>Space colors</strong><span>Blend two colors into your own Space identity.</span></div><div className="dual-color-picker"><label><span>Primary</span><input type="color" disabled={!canManage} value={accent} onChange={e => setAccent(e.target.value)} /><code>{accent}</code></label><label><span>Secondary</span><input type="color" disabled={!canManage} value={accentTwo} onChange={e => setAccentTwo(e.target.value)} /><code>{accentTwo}</code></label><div className="dual-color-preview" style={{ background: `linear-gradient(135deg, ${accent}, ${accentTwo})` }} /></div></div>
        {canManage && <div className="setting-row"><div><strong>Space picture & banner</strong><span>Edit the Space picture or reposition the banner before it saves for everyone.</span></div><div className="settings-inline-actions"><button className="secondary-button compact" onClick={() => editCurrentImage('avatar')}><Icon name="edit" size={13}/> Edit Space picture</button><button className="secondary-button compact" onClick={() => editCurrentImage('banner')}><Icon name="edit" size={13}/> {bannerUrl ? 'Adjust banner' : 'Add banner'}</button>{avatarUrl && <button className="secondary-button compact" onClick={() => setAvatarUrl(null)}>Clear icon</button>}{bannerUrl && <button className="secondary-button compact" onClick={() => setBannerUrl(null)}>Clear banner</button>}</div></div>}
        <div className="setting-row align-start"><div><strong>Icon frame</strong><span>Decorate the Space icon without changing the uploaded artwork.</span></div><div className="icon-decoration-picker">{iconDecorations.map(item => <button type="button" disabled={!canManage} key={item.id} className={iconDecoration === item.id ? 'active' : ''} onClick={() => setIconDecoration(item.id)}><span className={`space-icon-decor icon-decor-${item.id}`} style={{ '--decor-accent': accent, '--decor-accent-2': accentTwo } as CSSProperties}><Avatar name={name || workspace.name} initials={workspace.initials} src={avatarUrl} size={32} accent={accent} /></span><small>{item.label}</small></button>)}</div></div>
      </section>

      <section className="settings-section"><div className="section-heading"><div><span className="eyebrow">ATMOSPHERE</span><h2>Background</h2></div></div><div className="background-grid">{backgrounds.map(item => <button disabled={!canManage} key={item.id} className={`background-card bg-${item.id} ${background === item.id ? 'active' : ''}`} onClick={() => { setBackground(item.id); window.dispatchEvent(new CustomEvent('spaces-background-preview', { detail: item.id })) }}><span>{item.label}</span>{background === item.id && <i><Icon name="check" size={13} /></i>}</button>)}</div></section>

      {canManage && <section className="settings-section"><div className="section-heading"><div><span className="eyebrow">CHANNEL ACCESS</span><h2>Channel permissions</h2><p>Discord-style overrides for @everyone, roles, and individual members. Allow, Neutral, or Deny each capability.</p></div></div><div className="channel-permission-list channel-acl-launch-list">{data?.channels.map(channel => <button className="channel-acl-launch" key={channel.id} onClick={() => setPermissionChannel(channel)}><span className="channel-acl-launch-icon"><Icon name={channel.kind === 'notes' ? 'notes' : 'hash'} size={16}/></span><span><strong>{channel.name}</strong><small>{channel.kind} · base post: {channel.postMinRole} · base notes: {channel.noteMinRole}</small></span><span className="channel-acl-launch-action">Edit permissions <Icon name="chevron" size={13}/></span></button>)}</div></section>}

      <section className={`settings-section danger-section ${isHub ? 'hub-protected-zone' : ''}`}>
        <div className="section-heading"><div><span className="eyebrow">MEMBERSHIP</span><h2>{isHub ? 'Permanent Space' : 'Danger zone'}</h2></div></div>
        {isHub ? <div className="hub-protected-card"><Icon name="shield" size={20}/><div><strong>Spaces - Hub is protected</strong><span>Every Spaces account belongs to the Hub. Members can mute it or hide it from their rail, but nobody can leave or delete it.</span></div><span className="protected-role-badge"><Icon name="lock" size={12}/> Permanent</span></div> : <div className="danger-actions">
          {!isOwner && <div><div><strong>Leave Space</strong><span>You can rejoin later with a valid invite.</span></div><button className="ghost-danger" onClick={() => void leave()}>Leave Space</button></div>}
          {isOwner && <div><div><strong>Delete Space</strong><span>Only the Owner can permanently remove this Space and its shared data.</span></div><button className="ghost-danger" onClick={() => void removeSpace()}>Delete Space</button></div>}
        </div>}
      </section>

      {dirty && <div className="sticky-save unsaved-bar"><span><strong>Careful — you have unsaved changes.</strong><small>Changes apply to everyone in this Space.</small></span><div><button className="secondary-button compact" disabled={busy} onClick={resetChanges}>Reset</button><button className="primary-button" disabled={busy || !name.trim()} onClick={() => void save()}>{busy ? 'Saving…' : 'Save changes'}</button></div></div>}
    </div>
  )
}
