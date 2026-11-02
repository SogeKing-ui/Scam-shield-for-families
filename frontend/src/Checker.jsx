import { useEffect, useRef, useState } from 'react'
import { api } from './api.js'
import { Sign, Tick } from './Signs.jsx'

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
    advice: 'Do not click, call, or send money or codes.',
  },
  medium: {
    title: 'Be careful',
    advice: 'This message has warning signs. Check with the real company using a phone number you already trust.',
  },
  low: {
    title: 'No strong warning signs',
    advice: 'That does not guarantee it is safe. If anything feels off, do not click anything.',
  },
}

const NEXT_STEPS = [
  'Do not click links or reply to the message.',
  'Never pay with gift cards, crypto, or a payment app because someone contacted you.',
  'Contact the real company using the number on your card, bill, or official website.',
  'Show the message to a family member or friend before you do anything.',
]

const CALM_STEPS = [
  'If anything feels off, do not click or reply.',
  'Ask someone you trust before you act on it.',
]

const REASONS_SHOWN = 3

const EXPLAIN_LANGS = [
  { code: 'en', label: 'English' },
  { code: 'es', label: 'Español' },
  { code: 'ht', label: 'Kreyòl' },
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
  const [showAllReasons, setShowAllReasons] = useState(false)
  const [pasteNote, setPasteNote] = useState('')
  const resultRef = useRef(null)
  const canPaste = typeof navigator !== 'undefined' && !!navigator.clipboard?.readText

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

  function resetResult() {
    setResult(null)
    setError('')
    setExplanation(null)
    setExplainError('')
    setShareMsg('')
    setShowAllReasons(false)
  }

  async function pasteFromClipboard() {
    setPasteNote('')
    try {
      const clip = await navigator.clipboard.readText()
      if (clip) {
        setText(clip.slice(0, MAX_CHARS))
        resetResult()
      } else {
        setPasteNote('Nothing to paste yet. Copy the message first.')
      }
    } catch {
      setPasteNote('Your browser did not allow that. Click in the box and press Ctrl+V (or ⌘V on a Mac).')
    }
  }

  async function check(e) {
    e.preventDefault()
    resetResult()
    setPasteNote('')
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

  useEffect(() => {
    if (!result || !resultRef.current) return
    const calm = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    resultRef.current.scrollIntoView({ behavior: calm ? 'auto' : 'smooth', block: 'start' })
    resultRef.current.focus({ preventScroll: true })
  }, [result])

  const level = result ? LEVELS[result.level] : null
  const reasons = result ? (showAllReasons ? result.signals : result.signals.slice(0, REASONS_SHOWN)) : []

  return (
    <>
      <form onSubmit={check} className="checker">
        <label htmlFor="message" className="field-label">Paste the message here</label>
        <p className="hint" id="message-hint">Copy the text or email on your phone or computer, then paste it into the box.</p>
        <textarea
          id="message"
          value={text}
          maxLength={MAX_CHARS}
          onChange={(e) => setText(e.target.value)}
          rows={7}
          aria-describedby="message-hint"
          placeholder="Example: Your account has been suspended. Click here to verify..."
        />
        <div className="tools">
          {canPaste && (
            <button type="button" className="secondary" onClick={pasteFromClipboard}>Paste from clipboard</button>
          )}
          {text && (
            <button type="button" className="quiet" onClick={() => { setText(''); resetResult(); setPasteNote('') }}>Clear</button>
          )}
          <span className="count">{text.length} of {MAX_CHARS}</span>
        </div>
        {pasteNote && <p role="status" className="hint">{pasteNote}</p>}
        <button type="submit" className="primary big" disabled={loading}>
          {loading ? 'Checking…' : 'Check this message'}
        </button>
        <p className="hint">Checking does not save your message. Only messages you choose to send to a family helper are stored, encrypted.</p>
        <div className="examples">
          <span>Not sure how it works? Try an example:</span>
          <div className="chips">
            {EXAMPLES.map((ex) => (
              <button type="button" className="chip" key={ex.label} onClick={() => { setText(ex.text); resetResult(); setPasteNote('') }}>
                {ex.label}
              </button>
            ))}
          </div>
        </div>
      </form>

      {error && <p role="alert" className="error">{error}</p>}

      {result && (
        <section className="result" aria-label="Result" ref={resultRef} tabIndex={-1}>
          <div className={`verdict ${result.level}`} role="status">
            <Sign level={result.level} />
            <div>
              <h2>{level.title}</h2>
              <p className="advice">{level.advice}</p>
              <p className="score">
                Risk score {result.score} out of 100
                <span className="meter" role="img" aria-label={`Risk score ${result.score} out of 100`}>
                  <span style={{ width: `${Math.max(result.score, 4)}%` }} />
                </span>
              </p>
            </div>
          </div>

          <h3>{result.level === 'low' ? 'Still unsure?' : 'What to do now'}</h3>
          <ul className="steps">
            {(result.level === 'low' ? CALM_STEPS : NEXT_STEPS).map((st) => (
              <li key={st}><Tick /><span>{st}</span></li>
            ))}
            {result.level !== 'low' && (
              <li>
                <Tick />
                <span>Report it at <a href="https://reportfraud.ftc.gov" target="_blank" rel="noopener noreferrer">reportfraud.ftc.gov</a>.</span>
              </li>
            )}
          </ul>

          <div className="block share">
            <h3>Show someone you trust</h3>
            {!user && (
              <p>
                A free account lets you send this result to a family member.{' '}
                <button type="button" className="link" onClick={onGoAuth}>Create an account</button>
              </p>
            )}
            {user && user.role === 'helper' && <p>Helper accounts receive messages. Ask the person you help to send them.</p>}
            {user && user.role === 'protected' && helpers && helpers.length === 0 && (
              <p>
                You have no helper yet. <button type="button" className="link" onClick={onGoFamily}>Invite one</button> and
                they can see the messages you choose to send.
              </p>
            )}
            {user && user.role === 'protected' && helpers && helpers.length > 0 && (
              <>
                <div className="controls">
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
                <p className="hint">They will see the whole message, including phone numbers. Nothing is sent unless you press this button.</p>
              </>
            )}
            {shareMsg && <p role="status" className="share-msg">{shareMsg}</p>}
          </div>

          <div className="block explain">
            <h3>Explain it in simple words</h3>
            <div className="controls">
              <div className="seg" role="group" aria-label="Language of the explanation">
                {EXPLAIN_LANGS.map((l) => (
                  <button key={l.code} type="button" aria-pressed={language === l.code} onClick={() => setLanguage(l.code)}>{l.label}</button>
                ))}
              </div>
              <button type="button" className="secondary" onClick={explain} disabled={explaining}>
                {explaining ? 'Writing…' : 'Explain with AI'}
              </button>
            </div>
            {!user && (
              <p className="hint">
                AI explanations are for signed-in accounts. Without one you get a built-in explanation.{' '}
                <button type="button" className="link" onClick={onGoAuth}>Sign in</button>
              </p>
            )}
            <p className="hint">
              This sends a copy of your message to an AI service (Claude). Phone numbers, emails, and long numbers are
              removed first, but names are not, so avoid pasting names.
            </p>
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
                {reasons.map((sg) => (
                  <li key={sg.id}>
                    <strong>{sg.title}</strong>
                    <span>{sg.explanation}</span>
                  </li>
                ))}
              </ul>
              {result.signals.length > REASONS_SHOWN && (
                <button type="button" className="quiet" aria-expanded={showAllReasons} onClick={() => setShowAllReasons((v) => !v)}>
                  {showAllReasons ? 'Show fewer reasons' : `Show all ${result.signals.length} reasons`}
                </button>
              )}
            </>
          )}

          {(result.urls.length > 0 || result.phones.length > 0) && (
            <>
              <h3>Links and numbers in the message</h3>
              <ul className="found">
                {result.urls.map((u) => (
                  <li key={u.url}><span className="tag">Do not open</span><code>{u.url}</code></li>
                ))}
                {result.phones.map((p) => (
                  <li key={p}><span className="tag">Do not call</span><code>{p}</code></li>
                ))}
              </ul>
            </>
          )}
        </section>
      )}
    </>
  )
}
