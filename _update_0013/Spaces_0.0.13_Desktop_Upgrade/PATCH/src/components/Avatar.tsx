import type { CSSProperties } from 'react'

export function Avatar({
  name,
  initials,
  src,
  size = 40,
  accent,
  className = '',
}: {
  name?: string
  initials?: string
  src?: string | null
  size?: number
  accent?: string
  className?: string
}) {
  const fallback = initials || (name ?? 'S').split(/\s+/).slice(0, 2).map(v => v[0] ?? '').join('').toUpperCase()
  const style = { '--avatar-size': `${size}px`, '--avatar-accent': accent ?? '#8b6ca8' } as CSSProperties
  return (
    <div className={`avatar ${className}`} style={style} title={name}>
      {src ? <img src={src} alt="" /> : <span>{fallback}</span>}
    </div>
  )
}
