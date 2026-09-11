import { useEffect, useMemo, useState } from 'react'
import { Icon } from './Icon'
import { Modal } from './Modal'
import { useSpaces } from '../state/SpacesContext'
import type { WorkspaceChannel, WorkspaceChannelPermissionAction, WorkspaceChannelPermissionOverwrite } from '../types/spaces'

const permissions: { id: WorkspaceChannelPermissionAction; label: string; note: string }[] = [
  { id: 'view_channel', label: 'View channel', note: 'See the channel and its content.' },
  { id: 'send_messages', label: 'Send messages', note: 'Post messages in chat channels.' },
  { id: 'attach_files', label: 'Attach files', note: 'Upload supported images and text files.' },
  { id: 'create_notes', label: 'Create notes', note: 'Create shared notes in this channel.' },
  { id: 'edit_notes', label: 'Edit notes', note: 'Edit existing shared notes.' },
  { id: 'delete_notes', label: 'Delete notes', note: 'Delete notes in this channel.' },
]

type Target = { type: 'everyone' | 'role' | 'member'; id: string; label: string; sublabel?: string }

type TriState = 'allow' | 'neutral' | 'deny'

export function ChannelPermissionsEditor({ channel, onClose }: { channel: WorkspaceChannel; onClose: () => void }) {
  const { data, listChannelPermissionOverwrites, saveChannelPermissionOverwrite, deleteChannelPermissionOverwrite, pushToast } = useSpaces()
  const [items, setItems] = useState<WorkspaceChannelPermissionOverwrite[]>([])
  const [selectedKey, setSelectedKey] = useState('everyone:everyone')
  const [draft, setDraft] = useState<Record<WorkspaceChannelPermissionAction, TriState>>(() => Object.fromEntries(permissions.map(item => [item.id, 'neutral'])) as Record<WorkspaceChannelPermissionAction, TriState>)
  const [busy, setBusy] = useState(true)

  const targets = useMemo<Target[]>(() => [
    { type: 'everyone', id: 'everyone', label: '@everyone', sublabel: 'Default permissions for this channel' },
    ...(data?.roles ?? []).map(role => ({ type: 'role' as const, id: role.id, label: role.name, sublabel: 'Role' })),
    ...(data?.members ?? []).map(member => ({ type: 'member' as const, id: member.id, label: member.displayName, sublabel: `@${member.username}` })),
  ], [data?.members, data?.roles])

  const selected = targets.find(target => `${target.type}:${target.id}` === selectedKey) ?? targets[0]

  useEffect(() => {
    setBusy(true)
    void listChannelPermissionOverwrites(channel.id).then(setItems).catch(error => pushToast(error instanceof Error ? error.message : 'Could not load channel permissions.', 'danger')).finally(() => setBusy(false))
  }, [channel.id, listChannelPermissionOverwrites, pushToast])

  useEffect(() => {
    if (!selected) return
    const current = items.find(item => item.targetType === selected.type && item.targetId === selected.id)
    const next = Object.fromEntries(permissions.map(permission => [permission.id, current?.allow.includes(permission.id) ? 'allow' : current?.deny.includes(permission.id) ? 'deny' : 'neutral'])) as Record<WorkspaceChannelPermissionAction, TriState>
    setDraft(next)
  }, [items, selected])

  async function save() {
    if (!selected) return
    setBusy(true)
    try {
      const allow = permissions.map(item => item.id).filter(id => draft[id] === 'allow')
      const deny = permissions.map(item => item.id).filter(id => draft[id] === 'deny')
      const saved = await saveChannelPermissionOverwrite(channel.id, selected.type, selected.id, allow, deny)
      setItems(current => [...current.filter(item => !(item.targetType === saved.targetType && item.targetId === saved.targetId)), saved])
      pushToast(`Permissions saved for ${selected.label}.`, 'success')
    } catch (error) {
      pushToast(error instanceof Error ? error.message : 'Could not save channel permissions.', 'danger')
    } finally { setBusy(false) }
  }

  async function clear() {
    if (!selected) return
    setBusy(true)
    try {
      await deleteChannelPermissionOverwrite(channel.id, selected.type, selected.id)
      setItems(current => current.filter(item => !(item.targetType === selected.type && item.targetId === selected.id)))
      pushToast(`Overrides cleared for ${selected.label}.`, 'success')
    } catch (error) { pushToast(error instanceof Error ? error.message : 'Could not clear channel permissions.', 'danger') }
    finally { setBusy(false) }
  }

  return <Modal title={`# ${channel.name} permissions`} subtitle="Discord-style channel overrides. Allow and Deny beat the neutral Space defaults." onClose={onClose} wide>
    <div className="channel-acl-shell">
      <aside className="channel-acl-targets">
        <span className="eyebrow">ROLES / MEMBERS</span>
        {targets.map(target => <button key={`${target.type}:${target.id}`} className={selectedKey === `${target.type}:${target.id}` ? 'active' : ''} onClick={() => setSelectedKey(`${target.type}:${target.id}`)}><span className="acl-target-icon"><Icon name={target.type === 'member' ? 'user' : target.type === 'role' ? 'roles' : 'members'} size={14}/></span><span><strong>{target.label}</strong><small>{target.sublabel}</small></span></button>)}
      </aside>
      <section className="channel-acl-permissions">
        <div className="channel-acl-heading"><div><span className="eyebrow">OVERRIDES</span><h3>{selected?.label}</h3><p>Neutral inherits the Space or role default.</p></div><button className="secondary-button compact" disabled={busy} onClick={() => void clear()}>Clear overrides</button></div>
        <div className="channel-acl-list">
          {permissions.map(permission => <div className="channel-acl-row" key={permission.id}><div><strong>{permission.label}</strong><span>{permission.note}</span></div><div className="acl-tristate" role="group" aria-label={`${permission.label} permission`}><button className={draft[permission.id] === 'deny' ? 'active deny' : ''} onClick={() => setDraft(current => ({ ...current, [permission.id]: 'deny' }))} title="Deny"><Icon name="x" size={14}/></button><button className={draft[permission.id] === 'neutral' ? 'active neutral' : ''} onClick={() => setDraft(current => ({ ...current, [permission.id]: 'neutral' }))} title="Neutral">/</button><button className={draft[permission.id] === 'allow' ? 'active allow' : ''} onClick={() => setDraft(current => ({ ...current, [permission.id]: 'allow' }))} title="Allow"><Icon name="check" size={14}/></button></div></div>)}
        </div>
        <div className="channel-acl-footer"><span><Icon name="shield" size={13}/> Owner always keeps full access.</span><button className="primary-button" disabled={busy} onClick={() => void save()}>{busy ? 'Saving…' : 'Save permissions'}</button></div>
      </section>
    </div>
  </Modal>
}
