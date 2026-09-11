import type { SVGProps } from 'react'

export type IconName =
  | 'home' | 'hash' | 'chat' | 'notes' | 'members' | 'settings' | 'roles'
  | 'emoji' | 'plus' | 'search' | 'chevron' | 'send' | 'paperclip' | 'x'
  | 'menu' | 'sparkle' | 'logout' | 'edit' | 'trash' | 'shield' | 'bell'
  | 'activity' | 'command' | 'grid' | 'monitor' | 'tablet' | 'phone'
  | 'user' | 'check' | 'more' | 'download' | 'reply' | 'lock' | 'globe'
  | 'refresh' | 'rotate' | 'maximize' | 'minimize' | 'copy' | 'upload'

const paths: Record<IconName, string[]> = {
  home: ['M3 10.5 12 3l9 7.5', 'M5 9.5V21h14V9.5', 'M9 21v-7h6v7'],
  hash: ['M10 3 8 21', 'M16 3l-2 18', 'M4 9h16', 'M3 15h16'],
  chat: ['M4 5h16v11H8l-4 4V5Z'],
  notes: ['M6 3h9l3 3v15H6V3Z', 'M9 10h6', 'M9 14h6', 'M9 18h4'],
  members: ['M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2', 'M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z', 'M22 21v-2a4 4 0 0 0-3-3.87', 'M16 3.13a4 4 0 0 1 0 7.75'],
  settings: ['M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z', 'M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06-1.7 2.94-.08-.02a1.7 1.7 0 0 0-1.87.34l-.65.38a1.7 1.7 0 0 0-.84 1.68V22h-3.4v-.09a1.7 1.7 0 0 0-.84-1.68l-.65-.38a1.7 1.7 0 0 0-1.87-.34l-.08.02-1.7-2.94.06-.06A1.7 1.7 0 0 0 4.6 15l-.38-.65a1.7 1.7 0 0 0-1.52-.86H2v-3.4h.09a1.7 1.7 0 0 0 1.68-.84l.38-.65a1.7 1.7 0 0 0 .34-1.87l-.02-.08 2.94-1.7.06.06A1.7 1.7 0 0 0 9.34 4.6L10 4.22a1.7 1.7 0 0 0 .86-1.52V2h3.4v.09a1.7 1.7 0 0 0 .84 1.68l.65.38a1.7 1.7 0 0 0 1.87.34l.08-.02 1.7 2.94-.06.06A1.7 1.7 0 0 0 19.4 9.34l.38.65a1.7 1.7 0 0 0 1.52.86H22v3.4h-.09a1.7 1.7 0 0 0-1.68.84l-.83-.09Z'],
  roles: ['M12 3 4 7v5c0 5 3.5 8 8 9 4.5-1 8-4 8-9V7l-8-4Z', 'M9 12l2 2 4-4'],
  emoji: ['M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20Z', 'M8 14s1.5 2 4 2 4-2 4-2', 'M9 9h.01', 'M15 9h.01'],
  plus: ['M12 5v14', 'M5 12h14'],
  search: ['M21 21l-4.35-4.35', 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14Z'],
  chevron: ['m9 18 6-6-6-6'],
  send: ['m22 2-7 20-4-9-9-4L22 2Z', 'M22 2 11 13'],
  paperclip: ['m21.4 11.6-8.8 8.8a6 6 0 0 1-8.5-8.5l9.2-9.2a4 4 0 0 1 5.7 5.7l-9.2 9.2a2 2 0 0 1-2.8-2.8l8.5-8.5'],
  x: ['M18 6 6 18', 'M6 6l12 12'],
  menu: ['M4 6h16', 'M4 12h16', 'M4 18h16'],
  sparkle: ['m12 3 1.4 4.6L18 9l-4.6 1.4L12 15l-1.4-4.6L6 9l4.6-1.4L12 3Z', 'm19 15 .7 2.3L22 18l-2.3.7L19 21l-.7-2.3L16 18l2.3-.7L19 15Z'],
  logout: ['M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4', 'M16 17l5-5-5-5', 'M21 12H9'],
  edit: ['M12 20h9', 'M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4L16.5 3.5Z'],
  trash: ['M3 6h18', 'M8 6V4h8v2', 'M19 6l-1 15H6L5 6', 'M10 11v6', 'M14 11v6'],
  shield: ['M12 3 4 7v5c0 5 3.5 8 8 9 4.5-1 8-4 8-9V7l-8-4Z'],
  bell: ['M18 8a6 6 0 1 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9', 'M10 21h4'],
  activity: ['M3 12h4l2-7 4 14 2-7h6'],
  command: ['M9 6V5a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3v14a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3V5'],
  grid: ['M4 4h6v6H4z', 'M14 4h6v6h-6z', 'M4 14h6v6H4z', 'M14 14h6v6h-6z'],
  monitor: ['M3 4h18v12H3z', 'M8 20h8', 'M12 16v4'],
  tablet: ['M5 2h14v20H5z', 'M11 18h2'],
  phone: ['M7 2h10v20H7z', 'M11 18h2'],
  user: ['M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z', 'M4 21a8 8 0 0 1 16 0'],
  check: ['m5 12 4 4L19 6'],
  more: ['M5 12h.01', 'M12 12h.01', 'M19 12h.01'],
  download: ['M12 3v12', 'm7 10 5 5 5-5', 'M5 21h14'],
  reply: ['m9 17-5-5 5-5', 'M4 12h10a6 6 0 0 1 6 6v1'],
  lock: ['M5 10h14v11H5z', 'M8 10V7a4 4 0 0 1 8 0v3'],
  globe: ['M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20Z', 'M2 12h20', 'M12 2a15 15 0 0 1 0 20', 'M12 2a15 15 0 0 0 0 20'],
  refresh: ['M20 6v6h-6', 'M4 18v-6h6', 'M18.5 9a7 7 0 0 0-12-2L4 12', 'M5.5 15a7 7 0 0 0 12 2L20 12'],
  rotate: ['M4 7h10a6 6 0 0 1 6 6v1', 'm7 4-3 3 3 3', 'M20 17H10a6 6 0 0 1-6-6v-1', 'm17 20 3-3-3-3'],
  maximize: ['M8 3H3v5', 'm3 3 6 6', 'M16 21h5v-5', 'm21 21-6-6'],
  minimize: ['M9 9H4V4', 'm4 9 5-5', 'M15 15h5v5', 'm20 15-5 5'],
  copy: ['M8 8h11v11H8z', 'M5 16H4V5h11v1'],
  upload: ['M12 21V9', 'm7 14 5-5 5 5', 'M5 3h14'],
}

export function Icon({ name, size = 18, ...props }: SVGProps<SVGSVGElement> & { name: IconName; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>
      {paths[name].map((d, index) => <path key={index} d={d} />)}
    </svg>
  )
}
