import { useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import { Icon } from './Icon'
import type { WorkspaceEmoji } from '../types/spaces'
import { DEFAULT_EMOJIS, EMOJI_CATEGORIES, SPACES_EMOJIS, type EmojiCategoryId } from '../utils/default-emojis'

export function EmojiPicker({ emojis, onPick, onClose }: { emojis: WorkspaceEmoji[]; onPick: (value: string) => void; onClose: () => void }) {
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState<EmojiCategoryId>('frequent')
  const q = query.trim().toLowerCase()
  const native = useMemo(() => q ? DEFAULT_EMOJIS : (EMOJI_CATEGORIES.find(item => item.id === category)?.emoji ?? DEFAULT_EMOJIS), [category, q])
  const branded = useMemo(() => SPACES_EMOJIS.filter(item => !q || item.name.includes(q) || item.label.toLowerCase().includes(q)), [q])
  const custom = useMemo(() => emojis.filter(item => !q || item.name.toLowerCase().includes(q)), [emojis, q])

  const picker = (
    <div className="spaces-emoji-layer" role="dialog" aria-modal="true" aria-label="Emoji picker">
      <button type="button" className="spaces-emoji-scrim" aria-label="Close emoji picker" onPointerDown={onClose} />
      <aside className="spaces-emoji-picker spaces-emoji-picker-v11">
        <header className="sep-head"><div><strong>Emoji</strong><span>{q ? 'Search results' : EMOJI_CATEGORIES.find(item => item.id === category)?.label}</span></div><button type="button" onClick={onClose}><Icon name="x" size={14}/></button></header>
        <div className="sep-search"><Icon name="search" size={14}/><input autoFocus value={query} onChange={event => setQuery(event.target.value)} placeholder="Search Spaces or server emoji" /></div>
        <div className="sep-layout">
          <nav className="sep-categories" aria-label="Emoji categories">
            {EMOJI_CATEGORIES.map(item => <button type="button" key={item.id} className={category === item.id && !q ? 'active' : ''} title={item.label} onClick={() => { setCategory(item.id); setQuery('') }}><span>{item.emoji[0]}</span><small>{item.label}</small></button>)}
          </nav>
          <div className="sep-scroll">
            <section className="sep-section"><div className="sep-section-title"><strong>{q ? 'STANDARD' : EMOJI_CATEGORIES.find(item => item.id === category)?.label.toUpperCase()}</strong><span>{native.length}</span></div><div className="sep-native-grid">{native.map(emoji => <button type="button" key={emoji} title={emoji} onClick={() => onPick(emoji)}>{emoji}</button>)}</div></section>
            {branded.length > 0 && <section className="sep-section"><div className="sep-section-title"><strong>SPACES</strong><span>{branded.length}</span></div><div className="sep-brand-grid">{branded.map(emoji => <button type="button" key={emoji.name} title={`:${emoji.name}:`} onClick={() => onPick(`:${emoji.name}: `)}><img src={emoji.imageData} alt=""/><span>{emoji.label}</span></button>)}</div></section>}
            {custom.length > 0 && <section className="sep-section"><div className="sep-section-title"><strong>THIS SPACE</strong><span>{custom.length}</span></div><div className="sep-brand-grid sep-custom-grid">{custom.map(emoji => <button type="button" key={emoji.id} title={`:${emoji.name}:`} onClick={() => onPick(`:${emoji.name}: `)}><img src={emoji.imageData} alt=""/><span>:{emoji.name}:</span></button>)}</div></section>}
          </div>
        </div>
      </aside>
    </div>
  )

  return createPortal(picker, document.body)
}
