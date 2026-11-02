import { useState } from 'react'
import { api, friendlyError } from './api.js'

// Modes: login, signup, forgot (ask for an email link), reset (choose a new password from the emailed link).
export default function Auth({ onAuthed, resetToken, onResetDone }) {
  const [mode, setMode] = useState(resetToken ? 'reset' : 'login')
  const [confirm, setConfirm] = useState('')
  const [notice, setNotice] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [role, setRole] = useState('protected')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  function go(next) {
    if (mode === 'reset') onResetDone?.(false)  // leaving the reset page without changing anything
    setMode(next)
    setError('')
    setNotice('')
    setPassword('')
    setConfirm('')
  }

  async function submit(e) {
    e.preventDefault()
    setError('')
    setNotice('')
    setBusy(true)
    try {
      if (mode === 'forgot') {
        const data = await api('/api/auth/forgot', { method: 'POST', body: { email } })
        setNotice(data.message)
        return
      }
      if (mode === 'reset') {
        if (password !== confirm) {
          setError('The two passwords are not the same.')
          return
        }
        await api('/api/auth/reset', { method: 'POST', body: { token: resetToken, password } })
        onResetDone?.(true)
        setMode('login')
        setPassword('')
        setConfirm('')
        setNotice('Your password was changed. Please sign in with the new one.')
        return
      }
      const body = mode === 'login' ? { email, password } : { email, password, displayName, role }
      const data = await api(mode === 'login' ? '/api/auth/login' : '/api/auth/signup', { method: 'POST', body })
      onAuthed(data.user)
    } catch (err) {
      setError(friendlyError(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h2>{{ login: 'Sign in', signup: 'Create an account', forgot: 'Forgot your password?', reset: 'Choose a new password' }[mode]}</h2>
      <p className="lead">
        {{
          login: 'Sign in to send messages to your family helper, or to see what your family has sent you.',
          signup: 'An account lets a person and a trusted family member work together. Checking a message never needs one.',
          forgot: 'Enter your email and we will send you a link to choose a new one.',
          reset: 'Pick a new password for your account. You will be signed out on other devices.',
        }[mode]}
      </p>
      {notice && <p role="status" className="notice">{notice}</p>}
      <form onSubmit={submit} className="stack">
        {mode === 'signup' && (
          <>
            <label htmlFor="name">Your name</label>
            <input id="name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={60} required autoComplete="name" />
            <fieldset>
              <legend>I am…</legend>
              <label className="radio">
                <input type="radio" name="role" checked={role === 'protected'} onChange={() => setRole('protected')} />
                <span>someone who wants help staying safe from scams</span>
              </label>
              <label className="radio">
                <input type="radio" name="role" checked={role === 'helper'} onChange={() => setRole('helper')} />
                <span>a family member or friend who helps someone</span>
              </label>
            </fieldset>
          </>
        )}
        {mode !== 'reset' && (
          <>
            <label htmlFor="email">Email</label>
            <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
          </>
        )}
        {mode !== 'forgot' && (
          <>
            <label htmlFor="password">{mode === 'reset' ? 'New password' : 'Password'}</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={mode === 'signup' || mode === 'reset' ? 10 : undefined}
              maxLength={128}
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
            />
          </>
        )}
        {mode === 'reset' && (
          <>
            <label htmlFor="confirm">Type it again</label>
            <input id="confirm" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required minLength={10} maxLength={128} autoComplete="new-password" />
          </>
        )}
        {(mode === 'signup' || mode === 'reset') && <p className="privacy">Use at least 10 characters. A few random words works well.</p>}
        {error && <p role="alert" className="error">{error}</p>}
        <button type="submit" className="primary" disabled={busy}>
          {busy
            ? 'Please wait…'
            : { login: 'Sign in', signup: 'Create account', forgot: 'Send me a link', reset: 'Change my password' }[mode]}
        </button>
      </form>
      {mode === 'login' && (
        <p className="switch">
          <button type="button" className="link" onClick={() => go('forgot')}>Forgot your password?</button>
        </p>
      )}
      <p className="switch">
        {mode === 'login' ? 'New here? ' : mode === 'signup' ? 'Already have an account? ' : ''}
        {(mode === 'login' || mode === 'signup') && (
          <button type="button" className="link" onClick={() => go(mode === 'login' ? 'signup' : 'login')}>
            {mode === 'login' ? 'Create an account' : 'Sign in'}
          </button>
        )}
        {(mode === 'forgot' || mode === 'reset') && (
          <button type="button" className="link" onClick={() => go('login')}>Back to sign in</button>
        )}
      </p>
    </section>
  )
}
