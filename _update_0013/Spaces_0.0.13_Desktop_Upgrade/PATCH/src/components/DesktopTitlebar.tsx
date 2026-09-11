import { useEffect, useRef, useState } from 'react'
import { getCurrentWindow } from '@tauri-apps/api/window'
import { check } from '@tauri-apps/plugin-updater'
import { relaunch } from '@tauri-apps/plugin-process'
import { Icon } from './Icon'
import { SpacesLogo } from './SpacesLogo'

type AvailableUpdate = NonNullable<Awaited<ReturnType<typeof check>>>
type UpdateState = 'idle' | 'checking' | 'ready' | 'downloading' | 'installing' | 'error'

function inTauri() {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window
}

export function isTauriDesktopRuntime() {
  return inTauri() && !/Android|iPhone|iPad|iPod/i.test(navigator.userAgent)
}

export function DesktopTitlebar() {
  const isDesktop = isTauriDesktopRuntime()
  const [available, setAvailable] = useState<AvailableUpdate | null>(null)
  const [state, setState] = useState<UpdateState>('idle')
  const [panelOpen, setPanelOpen] = useState(false)
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState('')
  const lastCheck = useRef(0)

  useEffect(() => {
    if (!isDesktop) return

    let cancelled = false
    let timer = 0

    const runCheck = async (force = false) => {
      const now = Date.now()
      if (!force && now - lastCheck.current < 5 * 60 * 1000) return
      lastCheck.current = now
      setState(current => current === 'ready' ? current : 'checking')
      try {
        const next = await check({ timeout: 12000 })
        if (cancelled) return
        setAvailable(next)
        setState(next ? 'ready' : 'idle')
        setError('')
      } catch {
        // The first updater-ready build can run before the release endpoint is live.
        // Keep the UI quiet until a signed update is actually available.
        if (cancelled) return
        setState(available ? 'ready' : 'idle')
      }
    }

    timer = window.setTimeout(() => void runCheck(true), 4200)
    const interval = window.setInterval(() => void runCheck(true), 30 * 60 * 1000)
    const onFocus = () => void runCheck(false)
    window.addEventListener('focus', onFocus)

    return () => {
      cancelled = true
      window.clearTimeout(timer)
      window.clearInterval(interval)
      window.removeEventListener('focus', onFocus)
    }
  }, [isDesktop])

  if (!isDesktop) return null

  const appWindow = getCurrentWindow()

  const installUpdate = async () => {
    if (!available || state === 'downloading' || state === 'installing') return
    setPanelOpen(true)
    setState('downloading')
    setProgress(0)
    setError('')
    let downloaded = 0
    let contentLength = 0

    try {
      await available.downloadAndInstall(event => {
        if (event.event === 'Started') {
          contentLength = event.data.contentLength ?? 0
          setState('downloading')
        } else if (event.event === 'Progress') {
          downloaded += event.data.chunkLength
          if (contentLength > 0) setProgress(Math.min(99, Math.round((downloaded / contentLength) * 100)))
        } else if (event.event === 'Finished') {
          setProgress(100)
          setState('installing')
        }
      })

      // Windows exits automatically as the installer takes over. Other desktop
      // platforms relaunch explicitly after installation.
      if (!/Windows/i.test(navigator.userAgent)) await relaunch()
    } catch (caught) {
      setState('error')
      setError(caught instanceof Error ? caught.message : 'Spaces could not install this update.')
    }
  }

  const notes = available?.body?.trim() || 'A new Spaces build is ready to install.'

  return (
    <>
      <div className="desktop-titlebar" data-tauri-drag-region onDoubleClick={() => void appWindow.toggleMaximize()}>
        <div className="desktop-titlebar-brand" data-tauri-drag-region>
          <span className="titlebar-mark titlebar-buildings" data-tauri-drag-region><SpacesLogo title="Spaces" /></span>
          <strong data-tauri-drag-region>Spaces</strong>
          <small data-tauri-drag-region>0.0.13</small>
        </div>
        <div className="desktop-window-controls" onDoubleClick={event => event.stopPropagation()}>
          {available && (
            <button
              className={`titlebar-update ${state === 'downloading' || state === 'installing' ? 'working' : ''}`}
              title={`Spaces ${available.version} is available`}
              aria-label={`Download Spaces ${available.version}`}
              onClick={() => setPanelOpen(value => !value)}
            >
              <Icon name="download" size={15} />
              <i />
            </button>
          )}
          <button className="window-control" title="Minimize" aria-label="Minimize" onClick={() => void appWindow.minimize()}>
            <span className="window-minimize" />
          </button>
          <button className="window-control" title="Maximize" aria-label="Maximize" onClick={() => void appWindow.toggleMaximize()}>
            <span className="window-maximize" />
          </button>
          <button className="window-control window-close" title="Close" aria-label="Close" onClick={() => void appWindow.close()}>
            <Icon name="x" size={14} />
          </button>
        </div>
      </div>

      {available && panelOpen && (<>
        <button className="desktop-update-scrim" aria-label="Close update panel" onPointerDown={() => setPanelOpen(false)} />
        <aside className="desktop-update-card page-enter" aria-label="Spaces update">
          <header>
            <span className="update-card-icon"><Icon name="download" size={17} /></span>
            <span>
              <small>SPACES UPDATE</small>
              <strong>{available.version} is ready</strong>
            </span>
            <button aria-label="Close update panel" onClick={() => setPanelOpen(false)}><Icon name="x" size={13} /></button>
          </header>
          <p>{notes}</p>
          {(state === 'downloading' || state === 'installing') && (
            <div className="update-progress-wrap">
              <div className="update-progress"><i style={{ width: `${progress}%` }} /></div>
              <small>{state === 'installing' ? 'Installing… Spaces will restart.' : `Downloading… ${progress}%`}</small>
            </div>
          )}
          {state === 'error' && <div className="update-error">{error}</div>}
          <footer>
            <button className="secondary-button" disabled={state === 'downloading' || state === 'installing'} onClick={() => setPanelOpen(false)}>Later</button>
            <button className="primary-button" disabled={state === 'downloading' || state === 'installing'} onClick={() => void installUpdate()}>
              <Icon name="download" size={14} />
              {state === 'error' ? 'Try again' : state === 'downloading' ? 'Downloading…' : state === 'installing' ? 'Installing…' : 'Update now'}
            </button>
          </footer>
        </aside>
      </>)}
    </>
  )
}
