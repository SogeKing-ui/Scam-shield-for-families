import { useEffect, useState } from 'react'
import { api } from './api.js'

const MAX_CHARS = 5000

const EXAMPLES = [
  {
    label: 'Fake delivery text',
    text: 'USPS: Your package is on hold. Pay a $1.99 redelivery fee now at http://usps-redelivery-help.top/pay or it will be returned. Urgent.',
  },
  {
    label: 'Fake IRS call',
    text: 'FINAL NOTICE: This is the IRS. There is a warrant for your arrest. Pay immediately with gift cards and call 561-555-0142. Do not tell anyone.',
  },
  {
    label: 'Normal message',
    text: 'Hey, are we still on for dinner at 7? I made a reservation near the parking garage.',
  },
]

const LEVELS = {
  high: {
    title: 'Very likely a scam',
    advice: 'Do not click any links, call any numbers in the message, or send money or codes.',
  },
  medium: {
    title: 'Be careful',
    advice: 'This message has warning signs. Check with the real company using a phone number you already trust.',
  },
  low: {
    title: 'No strong warning signs found',
    advice: "That does not guarantee it is safe. If anything feels off, do not click and ask someone you trust.",
  },
}

const NEXT_STEPS = [
  'Do not click links or reply to the message.',
  'Never pay with gift cards, crypto, or a payment app because someone contacted you.',
  'Contact the real company using the number on your card, bill, or official website.',
  'Show the message to a family member or friend before you do anything.',
]

export default function Checker({ user, onGoFamily, onGoAuth }) {
  const [text, setText] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [language, setLanguage] = useState('en')
  const [explanation, setExplanation] = useState(null)
  const [explaining, setExplaining] = useState(false)
  const [explainError, setExplainError] = useState('')
  const [helpers, setHelpers] = useState(null)
  const [helperId, setHelperId] = useState('')
  const [sharing, setSharing] = useState(false)
  const [shareMsg, setShareMsg] = useState('')

  // Reload the helper list when the person signs in and every time a result is shown, so a helper
  // who just linked (or was removed) is reflected right away.
  function refreshHelpers() {
    if (user && user.role === 'protected') {
      api('/api/links').then((d) => setHelpers(d.links)).catch(() => setHelpers([]))
    } else {
      setHelpers(null)
    }
  }

  useEffect(refreshHelpers, [user]) // eslint-disable-line react-hooks/exhaustive-deps

  async function share() {
    setShareMsg('')
    setSharing(true)
    try {
      const chosen = helperId || (helpers && helpers[0] && helpers[0].id)
      await api('/api/share', { method: 'POST', body: { text, helperId: Number(chosen) || undefined } })
      setShareMsg('Sent. Your helper can now see this message.')
    } catch (err) {
      setShareMsg(err.message)
    } finally {
      setSharing(false)
    }
  }

  async function explain() {
    setExplainError('')
    setExplanation(null)
    setExplaining(true)
    try {
      const res = await fetch('/api/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, language, consent: true }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.error || 'Something went wrong. Please try again.')
      setExplanation(data)
    } catch (err) {
      setExplainError(err.message === 'Failed to fetch' ? 'Cannot reach the checker. Is the server running?' : err.message)
    } finally {
      setExplaining(false)
    }
  }

  async function check(e) {
    e.preventDefault()
    setError('')
    setResult(null)
    setExplanation(null)
    setExplainError('')
    setShareMsg('')
    if (!text.trim()) {
      setError('Please paste a message first.')
      return
    }
    setLoading(true)
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.error || 'Something went wrong. Please try again.')
      setResult(data)
      refreshHelpers()
    } catch (err) {
      setError(err.message === 'Failed to fetch' ? 'Cannot reach the checker. Is the server running?' : err.message)
    } finally {
      setLoading(false)
    }
  }

  const level = result ? LEVELS[result.level] : null

  return (
    <>

      <form onSubmit={check}>
        <label htmlFor="message">Paste the message here</label>
        <textarea
          id="message"
          value={text}
          maxLength={MAX_CHARS}
          onChange={(e) => setText(e.target.value)}
          rows={8}
          placeholder="Example: Your account has been suspended. Click here to verify..."
        />
        <div className="row">
          <span className="count">{text.length} / {MAX_CHARS}</span>
          <div className="examples">
            <span>Try an example:</span>
            {EXAMPLES.map((ex) => (
              <button type="button" className="link" key={ex.label} onClick={() => { setText(ex.text); setResult(null); setError(''); setExplanation(null); setExplainError(''); setShareMsg('') }}>
                {ex.label}
              </button>
            ))}
          </div>
        </div>
        <button type="submit" className="primary" disabled={loading}>
          {loading ? 'Checking…' : 'Check this message'}
        </button>
        <p className="privacy">Checking a message does not save it. Only messages you choose to send to a family helper are stored (encrypted).</p>
      </form>

      {error && <p role="alert" className="error">{error}</p>}

      {result && (
        <section className={`result ${result.level}`} aria-live="polite">
          <div className="verdict">
            <h2>{level.title}</h2>
            <p className="score">Risk score: <strong>{result.score}</strong> out of 100</p>
            <div className="meter" role="img" aria-label={`Risk score ${result.score} out of 100`}>
              <div style={{ width: `${result.score}%` }} />
            </div>
            <p>{level.advice}</p>
          </div>

          <div className="share">
            <h3>Send to a family helper</h3>
            {!user && (
              <p className="privacy">
                <button type="button" className="link" onClick={onGoAuth}>Create an account</button> to send results to a trusted family member.
              </p>
            )}
            {user && user.role === 'helper' && <p className="privacy">Helper accounts receive messages. Ask the person you help to send them.</p>}
            {user && user.role === 'protected' && helpers && helpers.length === 0 && (
              <p className="privacy">
                You have no helper yet. <button type="button" className="link" onClick={onGoFamily}>Invite one</button> and they can see messages you choose to send.
              </p>
            )}
            {user && user.role === 'protected' && helpers && helpers.length > 0 && (
              <>
                <div className="explain-controls">
                  {helpers.length > 1 && (
                    <>
                      <label htmlFor="helper">Send to</label>
                      <select id="helper" value={helperId || helpers[0].id} onChange={(e) => setHelperId(e.target.value)}>
                        {helpers.map((h) => <option key={h.id} value={h.id}>{h.displayName}</option>)}
                      </select>
                    </>
                  )}
                  <button type="button" className="secondary" onClick={share} disabled={sharing}>
                    {sharing ? 'Sending…' : `Send to ${helpers.length === 1 ? helpers[0].displayName : 'my helper'}`}
                  </button>
                </div>
                <p className="privacy">They will see the full message, including any phone numbers. Nothing is sent unless you press this button.</p>
              </>
            )}
            {shareMsg && <p role="status" className="share-msg">{shareMsg}</p>}
          </div>

          <div className="explain">
            <h3>Explain it in simple words</h3>
            <div className="explain-controls">
              <label htmlFor="lang">Language</label>
              <select id="lang" value={language} onChange={(e) => setLanguage(e.target.value)}>
                <option value="en">English</option>
                <option value="es">Español</option>
                <option value="ht">Kreyòl ayisyen</option>
              </select>
              <button type="button" className="secondary" onClick={explain} disabled={explaining}>
                {explaining ? 'Writing…' : 'Explain with AI'}
              </button>
            </div>
            <p className="privacy">
              This sends a copy of your message to an AI service (Claude). Phone numbers, emails, and long numbers are
              removed first, but names are not, so avoid pasting names.
            </p>
            {!user && (
              <p className="privacy">
                AI explanations are for signed-in accounts. Without one you get a built-in explanation.{' '}
                <button type="button" className="link" onClick={onGoAuth}>Sign in</button>
              </p>
            )}
            {explainError && <p role="alert" className="error">{explainError}</p>}
            {explanation && (
              <div className="explanation" aria-live="polite">
                <p>{explanation.text}</p>
                <p className="source">
                  {explanation.source === 'claude' ? 'Written by AI (Claude). It can make mistakes.' : 'Built-in explanation.'}
                  {explanation.note ? ` ${explanation.note}` : ''}
                  {explanation.remainingToday != null ? ` AI explanations left today: ${explanation.remainingToday}.` : ''}
                </p>
              </div>
            )}
          </div>

          {result.signals.length > 0 && (
            <>
              <h3>Why we think so</h3>
              <ul className="reasons">
                {result.signals.map((s) => (
                  <li key={s.id}>
                    <strong>{s.title}</strong>
                    <span>{s.explanation}</span>
                  </li>
                ))}
              </ul>
            </>
          )}

          {(result.urls.length > 0 || result.phones.length > 0) && (
            <>
              <h3>Links and numbers we found</h3>
              <ul className="found">
                {result.urls.map((u) => (
                  <li key={u.url}>Link (do not open): <code>{u.url}</code></li>
                ))}
                {result.phones.map((p) => (
                  <li key={p}>Phone number (do not call): <code>{p}</code></li>
                ))}
              </ul>
            </>
          )}

          {result.level !== 'low' && (
            <>
              <h3>What to do</h3>
              <ul>
                {NEXT_STEPS.map((s) => <li key={s}>{s}</li>)}
                <li>Report it at <a href="https://reportfraud.ftc.gov" target="_blank" rel="noopener noreferrer">reportfraud.ftc.gov</a>.</li>
              </ul>
            </>
          )}
        </section>
      )}

    </>
  )
}
