import type { ReactNode } from 'react'
import type { ContentFilterLevel } from '../state/PreferencesContext'
import type { WorkspaceEmoji } from '../types/spaces'
import { filterContent } from '../utils/content-filter'
import { SPACES_EMOJIS } from '../utils/default-emojis'

const TOKEN_RE = /(:[a-zA-Z0-9_]{1,32}:|https?:\/\/[^\s]+|@[a-zA-Z0-9_.-]{1,32}|#[a-zA-Z0-9_-]{1,48}|\*\*[^*\n]+\*\*|`[^`\n]+`|\|\|[^|\n]+\|\|)/g

export function renderRichText(text: string, emojis: WorkspaceEmoji[], level: ContentFilterLevel = 'none'): ReactNode[] {
  const filtered = filterContent(text, level)
  const emojiMap = new Map(emojis.map(emoji => [emoji.name.toLowerCase(), emoji]))
  const presetEmojiMap = new Map(SPACES_EMOJIS.map(emoji => [emoji.name.toLowerCase(), emoji]))
  const parts = filtered.split(TOKEN_RE)

  return parts.map((part, index) => {
    const emojiMatch = /^:([a-zA-Z0-9_]{1,32}):$/.exec(part)
    const emojiName = emojiMatch?.[1].toLowerCase()
    const emoji = emojiName ? emojiMap.get(emojiName) : null
    const preset = emojiName ? presetEmojiMap.get(emojiName) : null
    if (emoji) return <img className="inline-emoji" key={`${part}-${index}`} src={emoji.imageData} alt={`:${emoji.name}:`} title={`:${emoji.name}:`} />
    if (preset) return <img className="inline-emoji inline-emoji-spaces" key={`${part}-${index}`} src={preset.imageData} alt={`:${preset.name}:`} title={`:${preset.name}:`} />

    if (/^https?:\/\//i.test(part)) {
      return <a className="rich-link" key={index} href={part} target="_blank" rel="noreferrer">{part}</a>
    }
    if (/^@[a-zA-Z0-9_.-]{1,32}$/.test(part)) return <span className="rich-mention" key={index}>{part}</span>
    if (/^#[a-zA-Z0-9_-]{1,48}$/.test(part)) return <span className="rich-channel" key={index}>{part}</span>
    if (/^\*\*[^*\n]+\*\*$/.test(part)) return <strong className="rich-bold" key={index}>{part.slice(2, -2)}</strong>
    if (/^`[^`\n]+`$/.test(part)) return <code className="rich-code" key={index}>{part.slice(1, -1)}</code>
    if (/^\|\|[^|\n]+\|\|$/.test(part)) return <span className="rich-spoiler" tabIndex={0} key={index}>{part.slice(2, -2)}</span>
    return <span key={index}>{part}</span>
  })
}
