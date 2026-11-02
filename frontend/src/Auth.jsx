import { useState } from 'react'
import { api, friendlyError } from './api.js'
import { translateError, useLang, useT } from './i18n.js'

// Modes: login, signup, forgot (ask for an email link), reset (choose a new password from the emailed link).
export default function Auth({ onAuthed, resetToken, onResetDone }) {
  const t = useT()
  const lang = useLang()
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
        await api('/api/auth/forgot', { method: 'POST', body: { email, lang } })
        setNotice(t('forgotSent'))
        return
      }
      if (mode === 'reset') {
        if (password !== confirm) {
          setError(t('mismatch'))
          return
        }
        await api('/api/auth/reset', { method: 'POST', body: { token: resetToken, password } })
        onResetDone?.(true)
        setMode('login')
        setPassword('')
        setConfirm('')
        setNotice(t('changed'))
        return
      }
      const body = mode === 'login' ? { email, password } : { email, password, displayName, role, lang }
      const data = await api(mode === 'login' ? '/api/auth/login' : '/api/auth/signup', { method: 'POST', body })
      onAuthed(data.user)
    } catch (err) {
      setError(translateError(friendlyError(err), lang))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h2>{t({ login: 'titleLogin', signup: 'titleSignup', forgot: 'titleForgot', reset: 'titleReset' }[mode])}</h2>
      <p className="lead">{t({ login: 'leadLogin', signup: 'leadSignup', forgot: 'leadForgot', reset: 'leadReset' }[mode])}</p>
      {notice && <p role="status" className="notice">{notice}</p>}
      <form onSubmit={submit} className="stack">
        {mode === 'signup' && (
          <>
            <label htmlFor="name">{t('yourName')}</label>
            <input id="name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={60} required autoComplete="name" />
            <fieldset>
              <legend>{t('iAm')}</legend>
              <label className="radio">
                <input type="radio" name="role" checked={role === 'protected'} onChange={() => setRole('protected')} />
                <span>{t('roleProtected')}</span>
              </label>
              <label className="radio">
                <input type="radio" name="role" checked={role === 'helper'} onChange={() => setRole('helper')} />
                <span>{t('roleHelper')}</span>
              </label>
            </fieldset>
          </>
        )}
        {mode !== 'reset' && (
          <>
            <label htmlFor="email">{t('email')}</label>
            <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
          </>
        )}
        {mode !== 'forgot' && (
          <>
            <label htmlFor="password">{mode === 'reset' ? t('newPassword') : t('password')}</label>
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
            <label htmlFor="confirm">{t('again')}</label>
            <input id="confirm" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required minLength={10} maxLength={128} autoComplete="new-password" />
          </>
        )}
        {(mode === 'signup' || mode === 'reset') && <p className="privacy">{t('hint')}</p>}
        {error && <p role="alert" className="error">{error}</p>}
        <button type="submit" className="primary" disabled={busy}>
          {busy ? t('wait') : t({ login: 'btnLogin', signup: 'btnSignup', forgot: 'btnForgot', reset: 'btnReset' }[mode])}
        </button>
      </form>
      {mode === 'login' && (
        <p className="switch">
          <button type="button" className="link" onClick={() => go('forgot')}>{t('forgotLink')}</button>
        </p>
      )}
      <p className="switch">
        {mode === 'login' ? t('newHere') : mode === 'signup' ? t('haveAccount') : ''}
        {(mode === 'login' || mode === 'signup') && (
          <button type="button" className="link" onClick={() => go(mode === 'login' ? 'signup' : 'login')}>
            {mode === 'login' ? t('titleSignup') : t('titleLogin')}
          </button>
        )}
        {(mode === 'forgot' || mode === 'reset') && (
          <button type="button" className="link" onClick={() => go('login')}>{t('back')}</button>
        )}
      </p>
    </section>
  )
}
