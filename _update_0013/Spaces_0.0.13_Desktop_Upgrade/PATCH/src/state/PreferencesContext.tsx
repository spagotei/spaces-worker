import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

export type ContentFilterLevel = 'none' | 'low' | 'medium' | 'high'
export type MessageDensity = 'comfortable' | 'compact'
export type NotificationLevel = 'all' | 'mentions' | 'none'
export type AppTheme = 'obsidian' | 'midnight' | 'slate' | 'soft'
export type PresenceStatus = 'online' | 'idle' | 'dnd' | 'offline'

export type SpacesPreferences = {
  contentFilter: ContentFilterLevel
  messageDensity: MessageDensity
  reducedMotion: boolean
  glassEffects: boolean
  enterToSend: boolean
  showMemberRail: boolean
  notificationLevel: NotificationLevel
  desktopSounds: boolean
  appTheme: AppTheme
  presence: PresenceStatus
  customStatus: string
  appAccent: string
  hiddenWorkspaceIds: string[]
  mutedWorkspaceIds: string[]
  mutedChannelIds: string[]
  customCursor: boolean
}

const DEFAULTS: SpacesPreferences = {
  contentFilter: 'none',
  messageDensity: 'comfortable',
  reducedMotion: false,
  glassEffects: true,
  enterToSend: true,
  showMemberRail: true,
  notificationLevel: 'mentions',
  desktopSounds: false,
  appTheme: 'obsidian',
  presence: 'online',
  customStatus: '',
  appAccent: '#8b6ca8',
  hiddenWorkspaceIds: [],
  mutedWorkspaceIds: [],
  mutedChannelIds: [],
  customCursor: true,
}

const STORAGE_KEY = 'spaces.preferences.v1'

type PreferencesContextValue = {
  preferences: SpacesPreferences
  effectivePresence: PresenceStatus
  setPreference: <K extends keyof SpacesPreferences>(key: K, value: SpacesPreferences[K]) => void
  resetPreferences: () => void
}

const PreferencesContext = createContext<PreferencesContextValue | null>(null)

function loadPreferences(): SpacesPreferences {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return DEFAULTS
    const parsed = JSON.parse(raw) as Partial<SpacesPreferences>
    return { ...DEFAULTS, ...parsed }
  } catch {
    return DEFAULTS
  }
}

export function PreferencesProvider({ children }: { children: ReactNode }) {
  const [preferences, setPreferences] = useState<SpacesPreferences>(loadPreferences)
  const [effectivePresence, setEffectivePresence] = useState<PresenceStatus>(() => loadPreferences().presence)

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(preferences))
    document.documentElement.dataset.motion = preferences.reducedMotion ? 'reduced' : 'full'
    document.documentElement.dataset.glass = preferences.glassEffects ? 'on' : 'off'
    document.documentElement.dataset.density = preferences.messageDensity
    document.documentElement.dataset.theme = preferences.appTheme
    document.documentElement.dataset.presence = preferences.presence
    document.documentElement.style.setProperty('--app-accent', preferences.appAccent)
  }, [preferences])

  useEffect(() => {
    if (preferences.presence !== 'online') { setEffectivePresence(preferences.presence); return }
    let timer = window.setTimeout(() => setEffectivePresence('idle'), 5 * 60 * 1000)
    const wake = () => { setEffectivePresence('online'); window.clearTimeout(timer); timer = window.setTimeout(() => setEffectivePresence('idle'), 5 * 60 * 1000) }
    const events: (keyof WindowEventMap)[] = ['pointerdown','keydown','focus']
    events.forEach(name => window.addEventListener(name, wake, { passive: true }))
    return () => { window.clearTimeout(timer); events.forEach(name => window.removeEventListener(name, wake)) }
  }, [preferences.presence])

  const value = useMemo<PreferencesContextValue>(() => ({
    preferences,
    effectivePresence,
    setPreference: (key, next) => setPreferences(current => ({ ...current, [key]: next })),
    resetPreferences: () => setPreferences(DEFAULTS),
  }), [effectivePresence, preferences])

  return <PreferencesContext.Provider value={value}>{children}</PreferencesContext.Provider>
}

export function usePreferences() {
  const value = useContext(PreferencesContext)
  if (!value) throw new Error('usePreferences must be used inside PreferencesProvider.')
  return value
}
