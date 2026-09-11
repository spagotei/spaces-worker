import { useEffect, useRef, useState, type CSSProperties } from 'react'
import { createPortal } from 'react-dom'
import { Icon } from './Icon'

export type GlassSelectOption = { value: string; label: string }

export function GlassSelect({ value, options, onChange, disabled = false, ariaLabel }: {
  value: string
  options: GlassSelectOption[]
  onChange: (value: string) => void
  disabled?: boolean
  ariaLabel?: string
}) {
  const buttonRef = useRef<HTMLButtonElement>(null)
  const [open, setOpen] = useState(false)
  const [rect, setRect] = useState<DOMRect | null>(null)
  const selected = options.find(option => option.value === value) ?? options[0]

  function toggle() {
    if (disabled) return
    const next = !open
    setRect(buttonRef.current?.getBoundingClientRect() ?? null)
    setOpen(next)
  }

  useEffect(() => {
    if (!open) return
    const close = () => setOpen(false)
    const onKey = (event: KeyboardEvent) => event.key === 'Escape' && close()
    window.addEventListener('resize', close)
    window.addEventListener('scroll', close, true)
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('resize', close)
      window.removeEventListener('scroll', close, true)
      window.removeEventListener('keydown', onKey)
    }
  }, [open])

  const menuStyle = rect ? {
    left: Math.min(rect.left, window.innerWidth - Math.max(190, rect.width) - 10),
    top: Math.min(rect.bottom + 7, window.innerHeight - Math.min(300, options.length * 42 + 20)),
    minWidth: Math.max(190, rect.width),
  } as CSSProperties : undefined

  return <span className={`glass-select ${disabled ? 'disabled' : ''}`}>
    <button ref={buttonRef} type="button" className="glass-select-trigger" disabled={disabled} aria-label={ariaLabel} aria-expanded={open} onClick={toggle}>
      <span>{selected?.label ?? value}</span><Icon name="chevron" size={12}/>
    </button>
    {open && rect && createPortal(<>
      <button className="glass-select-scrim" aria-label="Close dropdown" onPointerDown={() => setOpen(false)}/>
      <div className="glass-select-menu page-enter" style={menuStyle} role="listbox" aria-label={ariaLabel}>
        {options.map(option => <button type="button" role="option" aria-selected={option.value === value} className={option.value === value ? 'active' : ''} key={option.value} onClick={() => { onChange(option.value); setOpen(false) }}><span>{option.label}</span>{option.value === value && <Icon name="check" size={13}/>}</button>)}
      </div>
    </>, document.body)}
  </span>
}
