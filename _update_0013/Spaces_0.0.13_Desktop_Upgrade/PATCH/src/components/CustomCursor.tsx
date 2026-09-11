import { useEffect, useRef, useState } from 'react'
import { usePreferences } from '../state/PreferencesContext'

export function CustomCursor() {
  const { preferences } = usePreferences()
  const cursorRef = useRef<HTMLDivElement>(null)
  const [enabled, setEnabled] = useState(false)

  useEffect(() => {
    const fine = window.matchMedia('(pointer:fine)')
    const update = () => setEnabled(preferences.customCursor && fine.matches)
    update()
    fine.addEventListener?.('change', update)
    return () => fine.removeEventListener?.('change', update)
  }, [preferences.customCursor])

  useEffect(() => {
    document.documentElement.dataset.spacesCustomCursor = enabled ? 'true' : 'false'
    return () => { delete document.documentElement.dataset.spacesCustomCursor }
  }, [enabled])

  useEffect(() => {
    if (!enabled) return
    let frame = 0
    const move = (event: PointerEvent) => {
      if (frame) cancelAnimationFrame(frame)
      frame = requestAnimationFrame(() => {
        if (!cursorRef.current) return
        cursorRef.current.style.transform = `translate3d(${event.clientX}px, ${event.clientY}px, 0)`
        cursorRef.current.dataset.visible = 'true'
        const target = event.target instanceof Element ? event.target : null
        cursorRef.current.dataset.hot = String(Boolean(target?.closest('button,a,input,textarea,select,[role="button"]')))
      })
    }
    const leave = () => { if (cursorRef.current) cursorRef.current.dataset.visible = 'false' }
    window.addEventListener('pointermove', move, { passive: true })
    document.documentElement.addEventListener('mouseleave', leave)
    return () => {
      if (frame) cancelAnimationFrame(frame)
      window.removeEventListener('pointermove', move)
      document.documentElement.removeEventListener('mouseleave', leave)
    }
  }, [enabled])

  if (!enabled) return null
  return <div ref={cursorRef} className="spaces-crosshair-cursor" aria-hidden="true"><i/><b/><span/></div>
}
