export type EmojiCategoryId = 'frequent' | 'smileys' | 'people' | 'nature' | 'food' | 'activity' | 'travel' | 'objects' | 'symbols'

export const EMOJI_CATEGORIES: { id: EmojiCategoryId; label: string; emoji: readonly string[] }[] = [
  { id: 'frequent', label: 'Frequent', emoji: ['😂','❤️','😭','🔥','✨','👍','🥳','👀','💀','✅','🎉','🙏','💜','🫡','🚀','☕'] },
  { id: 'smileys', label: 'Smileys', emoji: ['😀','😃','😄','😁','😆','😅','😂','🤣','😊','🙂','🙃','😉','😍','🥰','😘','😎','🤩','🥳','😴','🤔','🫡','🤨','😐','😑','😶','🙄','😏','😮','😱','😢','😭','😤','😡','🤯','🥶','🥵','🤢','🤮','🤧','😇','🤠','🤡','👻','💀','👽','🤖','🎃'] },
  { id: 'people', label: 'People', emoji: ['👍','👎','👏','🙌','🤝','🙏','💪','👀','🧠','🫶','👋','🤟','✌️','🤞','👌','🫵','💅','🧑‍💻','🧑‍🎨','🧑‍🚀'] },
  { id: 'nature', label: 'Nature', emoji: ['🐼','🦝','🐶','🐱','🦊','🐻','🐸','🐵','🦋','🌸','🌿','🍀','🌙','☀️','⭐','🌈','❄️','🔥','🌊','☁️'] },
  { id: 'food', label: 'Food', emoji: ['🍕','🍔','🍟','🌮','🍣','🍜','🍩','🍪','🍓','🍒','🍉','🍎','🥐','🍿','☕','🧋','🥤','🍰'] },
  { id: 'activity', label: 'Activity', emoji: ['🎮','🎧','🎵','🎸','⚽','🏀','🏈','🎾','🏆','🎯','🎲','🎨','🎬','📷','🎉','🎊'] },
  { id: 'travel', label: 'Travel', emoji: ['🚀','✈️','🚗','🚲','🚆','🛸','🏠','🏢','🌆','🌃','🗺️','🧭','⛺','🏖️','🌉','🚦'] },
  { id: 'objects', label: 'Objects', emoji: ['💻','📱','⌨️','🖥️','🎙️','📎','📌','📝','📚','💡','🔒','🔑','🔔','💬','🛠️','🧩','📦','🗂️'] },
  { id: 'symbols', label: 'Symbols', emoji: ['❤️','🧡','💛','💚','💙','💜','🖤','🤍','💯','✨','⚡','✅','❌','⚠️','➕','➖','❓','❗','♻️','™️'] },
]

export const DEFAULT_EMOJIS = [...new Set(EMOJI_CATEGORIES.flatMap(category => category.emoji))] as readonly string[]

function svgData(svg: string) {
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`
}

function lineIcon(paths: string[], accent = '#a986c4') {
  return svgData(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
    <g transform="translate(8 8) scale(2)" fill="none" stroke="${accent}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
      ${paths.map(path => `<path d="${path}"/>`).join('')}
    </g>
  </svg>`)
}

export const SPACES_EMOJIS = [
  { name: 'spaces_home', label: 'Home', imageData: lineIcon(['M3 10.5 12 3l9 7.5','M5 9.5V21h14V9.5','M9 21v-7h6v7']) },
  { name: 'spaces_chat', label: 'Chat', imageData: lineIcon(['M4 5h16v11H8l-4 4V5Z']) },
  { name: 'spaces_people', label: 'People', imageData: lineIcon(['M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2','M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z','M22 21v-2a4 4 0 0 0-3-3.87']) },
  { name: 'spaces_settings', label: 'Settings', imageData: lineIcon(['M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z','M12 2v3','M12 19v3','M4.9 4.9 7 7','m17 17 2.1 2.1','M2 12h3','M19 12h3','m4.9 19.1 2.1-2.1','M17 7l2.1-2.1']) },
  { name: 'spaces_emoji', label: 'Emoji', imageData: lineIcon(['M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20Z','M8 14s1.5 2 4 2 4-2 4-2','M9 9h.01','M15 9h.01']) },
  { name: 'spaces_notes', label: 'Notes', imageData: lineIcon(['M6 3h9l3 3v15H6V3Z','M9 10h6','M9 14h6','M9 18h4']) },
  { name: 'spaces_bell', label: 'Bell', imageData: lineIcon(['M18 8a6 6 0 1 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9','M10 21h4']) },
  { name: 'spaces_lock', label: 'Lock', imageData: lineIcon(['M5 10h14v11H5z','M8 10V7a4 4 0 0 1 8 0v3']) },
  { name: 'spaces_shield', label: 'Shield', imageData: lineIcon(['M12 3 4 7v5c0 5 3.5 8 8 9 4.5-1 8-4 8-9V7l-8-4Z']) },
  { name: 'spaces_search', label: 'Search', imageData: lineIcon(['M21 21l-4.35-4.35','M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14Z']) },
  { name: 'spaces_add', label: 'Add', imageData: lineIcon(['M12 5v14','M5 12h14']) },
  { name: 'spaces_reply', label: 'Reply', imageData: lineIcon(['m9 17-5-5 5-5','M4 12h10a6 6 0 0 1 6 6v1']) },
  { name: 'spaces_send', label: 'Send', imageData: lineIcon(['m22 2-7 20-4-9-9-4L22 2Z','M22 2 11 13']) },
  { name: 'spaces_attach', label: 'Attach', imageData: lineIcon(['m21.4 11.6-8.8 8.8a6 6 0 0 1-8.5-8.5l9.2-9.2a4 4 0 0 1 5.7 5.7l-9.2 9.2']) },
  { name: 'spaces_grid', label: 'Grid', imageData: lineIcon(['M4 4h6v6H4z','M14 4h6v6h-6z','M4 14h6v6H4z','M14 14h6v6h-6z']) },
  { name: 'spaces_spark', label: 'Spark', imageData: lineIcon(['m12 3 1.4 4.6L18 9l-4.6 1.4L12 15l-1.4-4.6L6 9l4.6-1.4L12 3Z']) },
  { name: 'spaces_activity', label: 'Activity', imageData: lineIcon(['M3 12h4l2-7 4 14 2-7h6']) },
  { name: 'spaces_monitor', label: 'Monitor', imageData: lineIcon(['M3 4h18v12H3z','M8 20h8','M12 16v4']) },
  { name: 'spaces_user', label: 'User', imageData: lineIcon(['M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z','M4 21a8 8 0 0 1 16 0']) },
  { name: 'spaces_check', label: 'Done', imageData: lineIcon(['m5 12 4 4L19 6']) },
] as const
