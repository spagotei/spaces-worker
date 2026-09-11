import { useRef, useState, type ChangeEvent } from 'react'
import { Icon } from '../../components/Icon'
import { useSpaces } from '../../state/SpacesContext'
import { hasWorkspacePermission } from '../../utils/permissions'
import { DEFAULT_EMOJIS, SPACES_EMOJIS } from '../../utils/default-emojis'

const MAX_EMOJI_BYTES = 64 * 1024
const ALLOWED_EMOJI_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif'])

function readDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result ?? ''))
    reader.onerror = () => reject(reader.error ?? new Error('Could not read emoji.'))
    reader.readAsDataURL(file)
  })
}

export function EmojiView() {
  const { data, profile, createEmoji, deleteEmoji, pushToast } = useSpaces()
  const emojis = data?.emojis ?? []
  const canManage = hasWorkspacePermission(data, profile?.id, 'manage_emojis')
  const input = useRef<HTMLInputElement>(null)
  const [name, setName] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [preview, setPreview] = useState('')
  const [busy, setBusy] = useState(false)

  async function choose(event: ChangeEvent<HTMLInputElement>) {
    const selected = event.target.files?.[0]
    event.target.value = ''
    if (!selected) return
    if (selected.size > MAX_EMOJI_BYTES) return pushToast('Custom emoji are limited to 64 KB.', 'danger')
    if (!ALLOWED_EMOJI_TYPES.has(selected.type)) return pushToast('Use PNG, JPEG, WebP or GIF for custom emoji.', 'danger')
    setFile(selected)
    setPreview(await readDataUrl(selected))
    if (!name) setName(selected.name.replace(/\.[^.]+$/, '').replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 32))
  }

  async function add() {
    if (!file || !preview || !name.trim()) return
    const clean = name.trim().replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 32)
    setBusy(true)
    try {
      await createEmoji(clean, file.type, preview)
      setName('')
      setFile(null)
      setPreview('')
    } finally { setBusy(false) }
  }

  return (
    <div className="view-scroll page-enter emoji-view">
      <div className="content-heading"><div><span className="eyebrow">CUSTOMIZATION</span><h1>Emoji</h1><p>Custom emoji belong to this Space and work in chat and comments.</p></div><span className="big-count">{emojis.length}<small>/100</small></span></div>
      <section className="default-emoji-section"><div className="section-heading"><div><span className="eyebrow">BUILT IN</span><h2>Spaces emoji</h2><p>A small branded set available in every Space.</p></div><span className="emoji-count-chip">{SPACES_EMOJIS.length} included</span></div><div className="spaces-preset-emoji-grid">{SPACES_EMOJIS.map(emoji => <button key={emoji.name} title={`:${emoji.name}:`} onClick={() => { void navigator.clipboard.writeText(`:${emoji.name}:`); pushToast(`:${emoji.name}: copied`, 'success') }}><img src={emoji.imageData} alt=""/><span>{emoji.label}</span><small>:{emoji.name}:</small></button>)}</div><details className="native-emoji-library"><summary>Browse standard emoji <span>{DEFAULT_EMOJIS.length}</span></summary><div className="default-emoji-grid">{DEFAULT_EMOJIS.map(emoji => <button key={emoji} title={`Copy ${emoji}`} onClick={() => { void navigator.clipboard.writeText(emoji); pushToast(`${emoji} copied`, 'success') }}>{emoji}</button>)}</div></details></section>
      {canManage && <section className="emoji-create-card polished-emoji-create"><button className="emoji-upload" onClick={() => input.current?.click()}>{preview ? <img src={preview} alt="Preview" /> : <><Icon name="plus" /><span>Choose image</span></>}</button><input hidden ref={input} type="file" accept=".png,.jpg,.jpeg,.webp,.gif" onChange={event => void choose(event)} /><div className="emoji-create-fields"><span className="eyebrow">CUSTOM EMOJI</span><label className="field-label">Emoji name<div className="input-shell"><span>:</span><input value={name} onChange={e => setName(e.target.value)} placeholder="raccoon" /><span>:</span></div></label><p>PNG, JPEG, WebP or GIF · 64 KB maximum.</p></div><button className="primary-button" disabled={!file || !name.trim() || busy} onClick={() => void add()}>{busy ? 'Adding…' : 'Add emoji'}</button></section>}
      <div className="section-heading custom-emoji-heading"><div><span className="eyebrow">THIS SPACE</span><h2>Custom emoji</h2></div></div>
      <section className="emoji-grid">{emojis.map(emoji => <article className="emoji-card" key={emoji.id}><div className="emoji-art"><img src={emoji.imageData} alt={`:${emoji.name}:`} /></div><strong>:{emoji.name}:</strong>{canManage && <button title="Delete emoji" onClick={() => void deleteEmoji(emoji.id)}><Icon name="trash" size={14} /></button>}</article>)}{!emojis.length && <div className="empty-state span-all"><div className="empty-icon"><Icon name="emoji" /></div><h3>No custom emoji yet</h3><p>Add the first one for this Space.</p></div>}</section>
    </div>
  )
}
