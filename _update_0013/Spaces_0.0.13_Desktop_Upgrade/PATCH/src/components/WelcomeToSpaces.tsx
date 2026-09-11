import { Icon } from './Icon'
import { SpacesLogo } from './SpacesLogo'

export function WelcomeToSpaces({ onContinue }: { onContinue: () => void }) {
  return (
    <div className="welcome-spaces-stage page-enter" role="dialog" aria-modal="true" aria-labelledby="welcome-spaces-title">
      <section className="welcome-spaces-card">
        <SpacesLogo className="welcome-spaces-logo" />
        <span className="eyebrow">WELCOME</span>
        <h1 id="welcome-spaces-title">Welcome to Spaces</h1>
        <p>Your people, projects, conversations, and shared notes with enough room to become its own world.</p>
        <div className="welcome-spaces-points">
          <div><Icon name="members" size={16}/><span><strong>Your people</strong><small>Build a Space around a community, team, or project.</small></span></div>
          <div><Icon name="chat" size={16}/><span><strong>More than chat</strong><small>Channels, notes, roles, media and shared work stay together.</small></span></div>
          <div><Icon name="settings" size={16}/><span><strong>Make it yours</strong><small>Customize your Space without changing the dark Spaces foundation.</small></span></div>
        </div>
        <button className="primary-button welcome-spaces-continue" onClick={onContinue}>Enter Spaces <Icon name="chevron" size={14}/></button>
        <small className="welcome-once-copy">This introduction only appears once on this device.</small>
      </section>
    </div>
  )
}
