import { useCallback, useEffect, useState } from 'react'
import { api } from './api.js'
import Auth from './Auth.jsx'
import Checker from './Checker.jsx'
import Family from './Family.jsx'

export default function App() {
  const [user, setUser] = useState(null)
  const [ready, setReady] = useState(false)
  // A password-reset email links to  /#reset=<token>. The token is kept in memory and removed from the address bar.
  const [resetToken, setResetToken] = useState(() => /^#reset=([0-9a-f]{64})$/.exec(window.location.hash)?.[1] || null)
  const [tab, setTab] = useState(resetToken ? 'auth' : 'check')
  const [unread, setUnread] = useState(0)

  const [resetKey, setResetKey] = useState(0)  // changes when a new reset link is opened, so the form starts fresh

  useEffect(() => {
    function pickUpResetLink() {
      const token = /^#reset=([0-9a-f]{64})$/.exec(window.location.hash)?.[1]
      if (token) {
        setResetToken(token)
        setResetKey((k) => k + 1)
        setTab('auth')
      }
      if (window.location.hash.startsWith('#reset=')) {
        window.history.replaceState(null, '', window.location.pathname + window.location.search)
      }
    }
    pickUpResetLink()
    window.addEventListener('hashchange', pickUpResetLink)
    return () => window.removeEventListener('hashchange', pickUpResetLink)
  }, [])

  useEffect(() => {
    api('/api/auth/me')
      .then((d) => { setUser(d.user); setUnread(d.unread || 0) })
      .catch(() => setUser(null))
      .finally(() => setReady(true))
  }, [])

  const onAuthed = useCallback((u) => {
    setUser(u)
    setTab('check')
    if (u.role === 'helper') api('/api/auth/me').then((d) => setUnread(d.unread || 0)).catch(() => {})
  }, [])

  async function signOut() {
    try { await api('/api/auth/logout', { method: 'POST' }) } catch { /* ignore */ }
    setUser(null)
    setUnread(0)
    setTab('check')
  }

  return (
    <main className="page">
      <header className="top">
        <div>
          <h1>Scam Shield</h1>
          <p className="lead">Paste a strange text or email and find out if it looks like a scam, and why.</p>
        </div>
        <nav aria-label="Main">
          <button type="button" className={tab === 'check' ? 'tab active' : 'tab'} onClick={() => setTab('check')}>Check a message</button>
          {user && (
            <button type="button" className={tab === 'family' ? 'tab active' : 'tab'} onClick={() => setTab('family')}>
              Family{unread > 0 ? ` (${unread} new)` : ''}
            </button>
          )}
          {ready && !user && (
            <button type="button" className={tab === 'auth' ? 'tab active' : 'tab'} onClick={() => setTab('auth')}>Sign in</button>
          )}
          {user && <button type="button" className="tab" onClick={signOut}>Sign out ({user.displayName})</button>}
        </nav>
      </header>

      <div hidden={tab !== 'check' || !!resetToken}>
        <Checker user={user} onGoFamily={() => setTab('family')} onGoAuth={() => setTab('auth')} />
      </div>
      {(resetToken || (tab === 'auth' && !user)) && (
        <Auth
          key={resetKey}
          onAuthed={onAuthed}
          resetToken={resetToken}
          onResetDone={(changed) => {
            setResetToken(null)
            if (changed) { setUser(null); setUnread(0) }  // a reset signs the account out everywhere
          }}
        />
      )}
      {tab === 'family' && user && !resetToken && (
        <Family user={user} onUnread={setUnread} onDeleted={() => { setUser(null); setUnread(0); setTab('check') }} />
      )}

      <footer>Scam Shield looks for common warning signs. It can be wrong. When in doubt, ask someone you trust.</footer>
    </main>
  )
}
