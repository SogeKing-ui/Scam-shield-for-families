import { useCallback, useEffect, useState } from 'react'
import { api } from './api.js'
import { LANGS, LangContext, detectLang, rememberLang, translate, translateError } from './i18n.js'
import Auth from './Auth.jsx'
import Checker from './Checker.jsx'
import Family from './Family.jsx'

export default function App() {
  const [lang, setLang] = useState(detectLang)
  const t = (key, vars) => translate(key, lang, vars)
  const [user, setUser] = useState(null)
  const [verifyStatus, setVerifyStatus] = useState(null)  // null, 'ok', or an error message
  const [resendNote, setResendNote] = useState('')
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
      const verifyToken = /^#verify=([0-9a-f]{64})$/.exec(window.location.hash)?.[1]
      if (verifyToken) {
        api('/api/auth/verify', { method: 'POST', body: { token: verifyToken } })
          .then(() => {
            setVerifyStatus('ok')
            return api('/api/auth/me').then((d) => setUser(d.user)).catch(() => {})  // refresh if signed in
          })
          .catch((err) => setVerifyStatus(err.message))
      }
      if (/^#(reset|verify)=/.test(window.location.hash)) {
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

  async function resendConfirmation() {
    setResendNote('')
    try {
      await api('/api/auth/resend-verification', { method: 'POST', body: { lang } })
      setResendNote(t('resent'))
    } catch (err) {
      setResendNote(translateError(err.message, lang))
    }
  }

  function changeLang(code) {
    setLang(code)
    rememberLang(code)
  }

  useEffect(() => { document.documentElement.lang = lang }, [lang])

  useEffect(() => {  // the "email confirmed" message goes away on its own
    if (verifyStatus !== 'ok') return undefined
    const timer = setTimeout(() => setVerifyStatus(null), 8000)
    return () => clearTimeout(timer)
  }, [verifyStatus])

  return (
    <LangContext.Provider value={lang}>
    <main className="page">
      <header className="top">
        <div>
          <h1>Scam Shield</h1>
          <p className="lead">{t('tagline')}</p>
        </div>
        <div className="lang">
          <label htmlFor="lang">{t('language')}</label>
          <select id="lang" value={lang} onChange={(e) => changeLang(e.target.value)}>
            {LANGS.map((l) => <option key={l.code} value={l.code}>{l.label}</option>)}
          </select>
        </div>
        <nav aria-label="Main">
          <button type="button" className={tab === 'check' ? 'tab active' : 'tab'} onClick={() => setTab('check')}>{t('tabCheck')}</button>
          {user && (
            <button type="button" className={tab === 'family' ? 'tab active' : 'tab'} onClick={() => setTab('family')}>
              {t('tabFamily')}{unread > 0 ? ` ${t('newCount', { n: unread })}` : ''}
            </button>
          )}
          {ready && !user && (
            <button type="button" className={tab === 'auth' ? 'tab active' : 'tab'} onClick={() => setTab('auth')}>{t('tabSignIn')}</button>
          )}
          {user && <button type="button" className="tab" onClick={signOut}>{t('signOut', { name: user.displayName })}</button>}
        </nav>
      </header>

      {verifyStatus === 'ok' && <p role="status" className="notice">{t('verified')}</p>}
      {verifyStatus && verifyStatus !== 'ok' && <p role="alert" className="error">{translateError(verifyStatus, lang)}</p>}
      {user && !user.verified && (
        <div className="notice" role="status">
          <p>{t('confirmNeed', { email: user.email })}</p>
          <button type="button" className="secondary" onClick={resendConfirmation}>{t('resend')}</button>
          {resendNote && <span className="resend-note"> {resendNote}</span>}
        </div>
      )}

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

      <footer>{t('footer')}</footer>
    </main>
    </LangContext.Provider>
  )
}
