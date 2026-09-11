import type { ContentFilterLevel } from '../state/PreferencesContext'

const PROFANITY = [
  'fuck', 'fucking', 'fucked', 'fucker',
  'shit', 'shitty',
  'bitch', 'bitches',
  'asshole', 'bullshit', 'motherfucker',
]

function maskWord(word: string, level: ContentFilterLevel): string {
  if (level === 'none') return word
  const chars = [...word]
  if (!chars.length) return word
  if (level === 'high') return '*'.repeat(chars.length)
  if (chars.length === 1) return '*'
  if (chars.length === 2) return `${chars[0]}*`

  // Low intentionally masks one inner character: Fuck -> F*ck.
  if (level === 'low') {
    return `${chars[0]}*${chars.slice(2).join('')}`
  }

  // Medium keeps only the first and final character: Fuck -> F**k.
  return `${chars[0]}${'*'.repeat(Math.max(1, chars.length - 2))}${chars.at(-1) ?? ''}`
}

export function filterContent(text: string, level: ContentFilterLevel): string {
  if (level === 'none' || !text) return text
  const terms = [...PROFANITY].sort((a, b) => b.length - a.length)
  const expression = new RegExp(`\\b(${terms.map(term => term.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&')).join('|')})\\b`, 'gi')
  return text.replace(expression, match => maskWord(match, level))
}

export function contentFilterExample(level: ContentFilterLevel): string {
  if (level === 'none') return 'Badword'
  if (level === 'low') return 'B*dword'
  if (level === 'medium') return 'B**w***'
  return '********'
}
