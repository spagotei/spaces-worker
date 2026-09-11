import { useEffect, useMemo, useRef, useState } from 'react'
import { Icon } from './Icon'
import { Modal } from './Modal'
import { cropImageSource, type ImagePreset } from '../utils/image'

type Crop = { zoom: number; x: number; y: number }

export function ImageCropper({ source, preset, title, onCancel, onSave }: {
  source: string
  preset: ImagePreset
  title: string
  onCancel: () => void
  onSave: (dataUrl: string) => void | Promise<void>
}) {
  const [crop, setCrop] = useState<Crop>({ zoom: 1, x: 50, y: 50 })
  const [busy, setBusy] = useState(false)
  const previewClass = preset === 'avatar' ? 'crop-preview-avatar' : 'crop-preview-banner'
  const previewStyle = useMemo(() => ({
    backgroundImage: `url(${source})`,
    backgroundSize: `${crop.zoom * 100}% auto`,
    backgroundPosition: `${crop.x}% ${crop.y}%`,
  }), [crop, source])

  async function commit() {
    if (busy) return
    setBusy(true)
    try {
      const dataUrl = await cropImageSource(source, preset, crop)
      await onSave(dataUrl)
    } finally {
      setBusy(false)
    }
  }

  return <Modal title={title} subtitle={preset === 'banner' ? 'Drag the framing controls until the banner sits exactly where you want it.' : 'Frame the Space picture before saving.'} onClose={onCancel}>
    <div className="image-cropper">
      <div className={`crop-preview ${previewClass}`} style={previewStyle}><span className="crop-safe-frame" /></div>
      <div className="crop-controls">
        <label><span>Zoom</span><input type="range" min="1" max="2.4" step="0.01" value={crop.zoom} onChange={e => setCrop(current => ({ ...current, zoom: Number(e.target.value) }))} /></label>
        <label><span>Horizontal</span><input type="range" min="0" max="100" step="1" value={crop.x} onChange={e => setCrop(current => ({ ...current, x: Number(e.target.value) }))} /></label>
        <label><span>Vertical</span><input type="range" min="0" max="100" step="1" value={crop.y} onChange={e => setCrop(current => ({ ...current, y: Number(e.target.value) }))} /></label>
      </div>
      <div className="crop-actions"><button className="secondary-button" onClick={() => setCrop({ zoom: 1, x: 50, y: 50 })}>Reset</button><button className="secondary-button" onClick={onCancel}>Cancel</button><button className="primary-button" disabled={busy} onClick={() => void commit()}><Icon name="check" size={14}/>{busy ? 'Saving…' : 'Use image'}</button></div>
    </div>
  </Modal>
}
