import { useCallback, useEffect, useState } from 'react'
import { api, friendlyError } from './api.js'
import Inbox from './Inbox.jsx'

export default function Family({ user, onUnread, onDeleted }) {
  const [links, setLinks] = useState(null)
  const [code, setCode] = useState('')
  const [invite, setInvite] = useState(null)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [deletePassword, setDeletePassword] = useState('')

  const load = useCallback(async () => {
    try {
      setLinks((await api('/api/links')).links)
    } catch (err) {
      setError(friendlyError(err))
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function createInvite() {
    setError(''); setMessage('')
    try { setInvite(await api('/api/links/invite', { method: 'POST' })) } catch (err) { setError(friendlyError(err)) }
  }

  async function accept(e) {
    e.preventDefault()
    setError(''); setMessage('')
    try {
      const data = await api('/api/links/accept', { method: 'POST', body: { code } })
      setMessage(`You are now linked with ${data.linked.displayName}.`)
      setCode('')
      load()
    } catch (err) {
      setError(friendlyError(err))
    }
  }

  async function unlink(person) {
    if (!window.confirm(`Remove ${person.displayName}? Messages shared between you will be deleted.`)) return
    setError(''); setMessage('')
    try { await api(`/api/links/${person.id}`, { method: 'DELETE' }); load() } catch (err) { setError(friendlyError(err)) }
  }

  async function deleteAccount(e) {
    e.preventDefault()
    setError('')
    if (!window.confirm('Delete your account and everything shared through it? This cannot be undone.')) return
    try {
      await api('/api/account/delete', { method: 'POST', body: { password: deletePassword } })
      onDeleted()
    } catch (err) {
      setError(friendlyError(err))
    }
  }

  const isProtected = user.role === 'protected'

  return (
    <div className="stack">
      {!isProtected && (
        <section className="card">
          <h2>Messages to look at</h2>
          <Inbox onUnread={onUnread} />
        </section>
      )}

      <section className="card">
        <h2>{isProtected ? 'Your family helpers' : 'People you help'}</h2>
        {links === null && <p className="hint">Loading…</p>}
        {links && links.length === 0 && (
          <p className="hint">
            {isProtected ? 'No helpers yet.' : 'You are not linked to anyone yet.'}
          </p>
        )}
        {links && links.length > 0 && (
          <ul className="people">
            {links.map((p) => (
              <li key={p.id}>
                <span>{p.displayName}</span>
                <button type="button" className="link" onClick={() => unlink(p)}>Remove</button>
              </li>
            ))}
          </ul>
        )}

        {isProtected ? (
          <>
            <button type="button" className="secondary" onClick={createInvite}>Invite a helper</button>
            {invite && (
              <div className="invite" role="status">
                <p>Give this code to your helper. It works once and expires in {invite.expiresInHours} hours.</p>
                <p className="code">{invite.code}</p>
                <p className="hint">Share it in person or by phone, not in a public place.</p>
              </div>
            )}
          </>
        ) : (
          <form onSubmit={accept} className="stack">
            <label htmlFor="code">Enter the code from the person you help</label>
            <input id="code" value={code} onChange={(e) => setCode(e.target.value)} placeholder="ABCD-EFGH" maxLength={12} autoComplete="off" required />
            <button type="submit" className="primary">Link</button>
          </form>
        )}
        {message && <p role="status" className="share-msg">{message}</p>}
        {error && <p role="alert" className="error">{error}</p>}
      </section>

      <section className="card account">
        <h2>Your account</h2>
        <p className="hint">Signed in as {user.displayName} ({user.email}).</p>
        <details>
          <summary>Delete my account</summary>
          <form onSubmit={deleteAccount} className="stack">
            <p>This deletes your account and everything shared through it. It cannot be undone.</p>
            <label htmlFor="delpw">Enter your password to confirm</label>
            <input id="delpw" type="password" value={deletePassword} onChange={(e) => setDeletePassword(e.target.value)} autoComplete="current-password" required />
            <button type="submit" className="danger">Delete my account</button>
          </form>
        </details>
      </section>
    </div>
  )
}
