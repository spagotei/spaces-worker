export function SpacesLogo({ className = '', title = 'Spaces' }: { className?: string; title?: string }) {
  return (
    <span className={`spaces-logo ${className}`.trim()} role="img" aria-label={title}>
      <i className="spaces-logo-building lb1" />
      <i className="spaces-logo-building lb2" />
      <i className="spaces-logo-building lb3" />
      <i className="spaces-logo-building lb4" />
      <i className="spaces-logo-building lb5" />
      <i className="spaces-logo-building lb6" />
    </span>
  )
}
