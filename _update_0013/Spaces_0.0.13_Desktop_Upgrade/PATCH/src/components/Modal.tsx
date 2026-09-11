import type { ReactNode } from 'react'
import { Icon } from './Icon'

export function Modal({ title, subtitle, children, onClose, wide = false }: {
  title: string
  subtitle?: string
  children: ReactNode
  onClose: () => void
  wide?: boolean
}) {
  return (
    <div className="modal-backdrop" onPointerDown={event => event.target === event.currentTarget && onClose()}>
      <section className={`modal ${wide ? 'modal-wide' : ''}`} role="dialog" aria-modal="true" aria-label={title}>
        <header className="modal-header">
          <div>
            <h2>{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close"><Icon name="x" /></button>
        </header>
        <div className="modal-body">{children}</div>
      </section>
    </div>
  )
}
