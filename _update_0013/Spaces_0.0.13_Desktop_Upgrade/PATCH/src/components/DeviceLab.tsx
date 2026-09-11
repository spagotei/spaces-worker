import { useMemo, useState } from 'react'
import { Icon } from './Icon'

type Preset = {
  id: string
  label: string
  icon: 'monitor' | 'tablet' | 'phone'
  width: number
  height: number
  chrome?: 'desktop' | 'mobile'
}

const presets: Preset[] = [
  { id: 'desktop', label: 'Desktop', icon: 'monitor', width: 1440, height: 900, chrome: 'desktop' },
  { id: 'laptop', label: 'Laptop', icon: 'monitor', width: 1280, height: 800, chrome: 'desktop' },
  { id: 'tablet', label: 'Tablet', icon: 'tablet', width: 1024, height: 768, chrome: 'mobile' },
  { id: 'phone-large', label: 'Phone XL', icon: 'phone', width: 430, height: 932, chrome: 'mobile' },
  { id: 'phone', label: 'Phone', icon: 'phone', width: 390, height: 844, chrome: 'mobile' },
]

export function DeviceLab() {
  const [presetId, setPresetId] = useState('desktop')
  const [scale, setScale] = useState(0.72)
  const [landscape, setLandscape] = useState(false)
  const [reloadKey, setReloadKey] = useState(0)
  const [frameOnly, setFrameOnly] = useState(false)

  const preset = useMemo(() => presets.find(item => item.id === presetId) ?? presets[0], [presetId])
  const width = landscape ? preset.height : preset.width
  const height = landscape ? preset.width : preset.height

  function choosePreset(id: string) {
    setPresetId(id)
    setLandscape(false)
    if (id.startsWith('phone')) setScale(0.72)
    else if (id === 'tablet') setScale(0.68)
    else setScale(0.72)
  }

  return (
    <div className={`device-lab ${frameOnly ? 'lab-frame-only' : ''}`}>
      <header className="lab-toolbar">
        <div className="lab-brand">
          <div className="brand-mark">S</div>
          <div><strong>Spaces Device Lab</strong><span>Live responsive simulator</span></div>
        </div>

        <div className="lab-presets">
          {presets.map(item => (
            <button key={item.id} className={presetId === item.id ? 'active' : ''} onClick={() => choosePreset(item.id)} title={`${item.width} × ${item.height}`}>
              <Icon name={item.icon} size={15} />
              {item.label}
              <span>{item.width}×{item.height}</span>
            </button>
          ))}
        </div>

        <div className="lab-actions">
          <button title="Rotate device" className={landscape ? 'active' : ''} onClick={() => setLandscape(value => !value)}><Icon name="rotate" size={15} /></button>
          <button title="Reload preview" onClick={() => setReloadKey(value => value + 1)}><Icon name="refresh" size={15} /></button>
          <button title={frameOnly ? 'Show lab controls' : 'Focus frame'} className={frameOnly ? 'active' : ''} onClick={() => setFrameOnly(value => !value)}><Icon name={frameOnly ? 'minimize' : 'maximize'} size={15} /></button>
        </div>

        <div className="lab-scale">
          <span>Scale</span>
          <input type="range" min="0.35" max="1" step="0.05" value={scale} onChange={event => setScale(Number(event.target.value))} />
          <strong>{Math.round(scale * 100)}%</strong>
        </div>

        <a className="secondary-button compact lab-open-raw" href="/" target="_blank" rel="noreferrer"><Icon name="globe" size={14} /> Open raw</a>
      </header>

      <main className="lab-stage">
        <div className="lab-dimensions"><span>{preset.label}{landscape ? ' · Landscape' : ''}</span><strong>{width} × {height}</strong></div>
        <div
          className={`device-frame device-${preset.chrome ?? 'desktop'} device-${preset.icon}`}
          style={{ width, height, transform: `scale(${scale})` }}
        >
          <div className="device-chrome">
            <span /><span /><span />
            <strong>{preset.label}</strong>
            <code>127.0.0.1:5173</code>
          </div>
          <iframe key={reloadKey} src="/?embed=1" title={`${preset.label} preview`} />
        </div>
      </main>

      <footer className="lab-footer">
        <span><Icon name="activity" size={14} /> Live frame — sign in, type, upload and navigate normally.</span>
        <span>VS Code → Simple Browser → http://127.0.0.1:5173/?lab=1</span>
      </footer>
    </div>
  )
}
