import { Icon } from './Icon'

export function ImagePreview({ src, name, onClose }: { src: string; name: string; onClose: () => void }) {
  return (
    <div className="image-preview-layer" role="dialog" aria-modal="true" aria-label={`Preview ${name}`}>
      <button className="image-preview-scrim" aria-label="Close image preview" onPointerDown={onClose} />
      <section className="image-preview-shell">
        <header><div><span>IMAGE PREVIEW</span><strong>{name}</strong></div><div><a href={src} download={name} title="Download"><Icon name="download" size={16}/></a><button onClick={onClose} title="Close"><Icon name="x" size={16}/></button></div></header>
        <div className="image-preview-canvas"><img src={src} alt={name} /></div>
      </section>
    </div>
  )
}
