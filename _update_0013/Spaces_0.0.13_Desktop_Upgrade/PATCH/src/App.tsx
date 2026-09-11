import { useEffect, useState, type ReactNode } from 'react'
import { DesktopTitlebar, isTauriDesktopRuntime } from './components/DesktopTitlebar'
import { CustomCursor } from './components/CustomCursor'
import { WelcomeToSpaces } from './components/WelcomeToSpaces'
import { LoginScreen } from './features/auth/LoginScreen'
import { AppShell } from './features/shell/AppShell'
import { PreferencesProvider } from './state/PreferencesContext'
import { SpacesProvider, useSpaces } from './state/SpacesContext'
import './styles/tokens.css'
import './styles/app.css'
import './styles/standalone-v2.css'
import './styles/standalone-v3.css'
import './styles/standalone-v4.css'
import './styles/standalone-v5.css'
import './styles/standalone-v6.css'
import './styles/standalone-v7.css'
import './styles/standalone-v8.css'
import './styles/standalone-v9.css'
import './styles/standalone-v10.css'
import './styles/standalone-v11.css'
import './styles/standalone-v12.css'
import './styles/standalone-v13.css'

function BootScreen() {
  return (
    <div className="boot-screen boot-city" aria-label="Opening Spaces">
      <div className="boot-city-mark" aria-hidden="true">
        <i className="building b1" /><i className="building b2" /><i className="building b3" /><i className="building b4" /><i className="building b5" /><i className="building b6" />
      </div>
      <div className="boot-wordmark boot-wordmark-v8"><strong className="boot-liquid-word">Spaces</strong></div>
      <div className="boot-launch-copy"><small>PRIVATE BETA</small><span>Opening your Space</span><i><b/><b/><b/></i></div>
    </div>
  )
}

function SpacesRoot() {
  const { session, loading } = useSpaces()
  const [welcomeDone, setWelcomeDone] = useState(() => localStorage.getItem('spaces.welcome.v1') === '1')

  if (loading && !session) return <BootScreen />
  if (!welcomeDone) return <WelcomeToSpaces onContinue={() => { localStorage.setItem('spaces.welcome.v1', '1'); setWelcomeDone(true) }} />
  if (!session) return <LoginScreen />
  return <AppShell />
}

function BootGate({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false)

  useEffect(() => {
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const timer = window.setTimeout(() => setReady(true), reduceMotion ? 650 : 3200)
    return () => window.clearTimeout(timer)
  }, [])

  if (!ready) return <BootScreen />
  return children
}

export default function App() {
  const desktopRuntime = isTauriDesktopRuntime()

  return (
    <>
      <DesktopTitlebar />
      <div className={desktopRuntime ? 'tauri-desktop-content' : undefined}>
        <PreferencesProvider>
          <SpacesProvider>
            <CustomCursor />
            <BootGate>
              <SpacesRoot />
            </BootGate>
          </SpacesProvider>
        </PreferencesProvider>
      </div>
    </>
  )
}
