import { useCallback, useEffect, useState } from 'react'
import { api, friendlyError } from './api.js'
import { Sign } from './Signs.jsx'

const LEVEL_LABEL = { high: 'Very likely a scam', medium: 'Be careful', low: 'No strong warning signs' }

export default function Inbox({ onUnread }) {
  const [items, setItems] = useState(null)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      const data = await api('/api/inbox')
      setItems(data.items)
      onUnread && onUnread(data.unread)
    } catch (err) {
      setError(friendlyError(err))
    }
  }, [onUnread])

  useEffect(() => { load() }, [load])

  async function markRead(id) {
    try { await api(`/api/inbox/${id}/read`, { method: 'POST' }); load() } catch (err) { setError(friendlyError(err)) }
  }

  async function remove(id) {
    try { await api(`/api/inbox/${id}`, { method: 'DELETE' }); load() } catch (err) { setError(friendlyError(err)) }
  }

  if (error) return <p role="alert" className="error">{error}</p>
  if (!items) return <p className="hint">Loading…</p>
  if (items.length === 0) return <p className="hint">Nothing here yet. When someone you help sends you a message to look at, it shows up here.</p>

  return (
    <ul className="inbox">
      {items.map((it) => (
        <li key={it.id} className={`inbox-item ${it.level}`}>
          <details onToggle={(e) => { if (e.currentTarget.open && !it.read) markRead(it.id) }}>
            <summary>
              <span className={`badge ${it.level}`}><Sign level={it.level} />{LEVEL_LABEL[it.level]}</span>
              <span className="from">From {it.from.displayName}</span>
              <span className="when">{new Date(it.createdAt * 1000).toLocaleString()}</span>
              {!it.read && <span className="new">New</span>}
            </summary>
            <p className="score-line">Risk score {it.score} out of 100</p>
            <pre className="msg">{it.message.text}</pre>
            {it.message.signals.length > 0 && (
              <details className="why">
                <summary>Why it looks this way ({it.message.signals.length} {it.message.signals.length === 1 ? 'reason' : 'reasons'})</summary>
                <ul className="reasons">
                  {it.message.signals.map((s) => (
                    <li key={s.id}><strong>{s.title}</strong><span>{s.explanation}</span></li>
                  ))}
                </ul>
              </details>
            )}
            {(it.message.urls.length > 0 || it.message.phones.length > 0) && (
              <ul className="found">
                {it.message.urls.map((u) => <li key={u.url}><span className="tag">Do not open</span><code>{u.url}</code></li>)}
                {it.message.phones.map((p) => <li key={p}><span className="tag">Do not call</span><code>{p}</code></li>)}
              </ul>
            )}
            <p className="hint">Call them on a number you already have to talk it through. Do not reply to the message.</p>
            <button type="button" className="secondary" onClick={() => remove(it.id)}>Delete this message</button>
          </details>
        </li>
      ))}
    </ul>
  )
}
