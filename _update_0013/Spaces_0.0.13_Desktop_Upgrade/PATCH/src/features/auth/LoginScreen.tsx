import { useState, type FormEvent } from 'react'
import { Icon } from '../../components/Icon'
import { useSpaces } from '../../state/SpacesContext'

export function LoginScreen() {
  const { login, loading, error, apiUrl } = useSpaces()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [localError, setLocalError] = useState('')

  async function submit(event: FormEvent) {
    event.preventDefault()
    setLocalError('')
    if (!username.trim() || !password) {
      setLocalError('Enter your username and password.')
      return
    }
    try {
      await login(username, password)
    } catch {
      // Context provides the server message.
    }
  }

  return (
    <main className="login-stage">
      <div className="login-network login-network-a" aria-hidden="true" />
      <div className="login-network login-network-b" aria-hidden="true" />
      <div className="ambient ambient-a" />
      <div className="ambient ambient-b" />
      <section className="login-brand">
        <div className="brand-mark brand-mark-large">S</div>
        <span className="eyebrow">PRIVATE BETA</span>
        <h1>Spaces</h1>
        <div className="login-slogan">Your Space, Your Needs.</div>
        <p>Your people, projects, conversations, and shared notes with enough room to become its own world.</p>
        <div className="login-feature-row">
          <span><Icon name="shield" size={15} /> Private beta</span>
          <span><Icon name="activity" size={15} /> Live backend</span>
          <span><Icon name="monitor" size={15} /> Desktop + app</span>
        </div>
      </section>

      <form className="login-card" onSubmit={submit}>
        <header>
          <div className="mini-lock"><Icon name="lock" /></div>
          <div>
            <span className="eyebrow">AUTHORIZED ACCESS</span>
            <h2>Welcome back</h2>
          </div>
        </header>

        <label className="field-label">
          Username
          <div className="input-shell"><span>@</span><input autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} placeholder="username" /></div>
        </label>

        <label className="field-label">
          Password
          <div className="input-shell"><Icon name="lock" size={15} /><input type="password" autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••••••" /></div>
        </label>

        {(localError || error) && <div className="form-error">{localError || error}</div>}

        <button className="primary-button primary-button-wide" disabled={loading}>
          {loading ? <span className="spinner" /> : <Icon name="sparkle" size={16} />}
          {loading ? 'Signing in…' : 'Enter Spaces'}
        </button>

        <footer>
          <span>Registration is closed.</span>
          <span className="endpoint-dot" />
          <span title={apiUrl}>Worker secured</span>
        </footer>
      </form>
    </main>
  )
}
