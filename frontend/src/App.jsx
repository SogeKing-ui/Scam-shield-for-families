import { useState } from 'react'

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

export default function App() {
  const [text, setText] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [language, setLanguage] = useState('en')
  const [explanation, setExplanation] = useState(null)
  const [explaining, setExplaining] = useState(false)
  const [explainError, setExplainError] = useState('')

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
    } catch (err) {
      setError(err.message === 'Failed to fetch' ? 'Cannot reach the checker. Is the server running?' : err.message)
    } finally {
      setLoading(false)
    }
  }

  const level = result ? LEVELS[result.level] : null

  return (
    <main className="page">
      <header>
        <h1>Scam Shield</h1>
        <p className="lead">Got a strange text, email, or voicemail transcript? Paste it here and we will tell you if it looks like a scam, and why.</p>
      </header>

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
              <button type="button" className="link" key={ex.label} onClick={() => { setText(ex.text); setResult(null); setError(''); setExplanation(null); setExplainError('') }}>
                {ex.label}
              </button>
            ))}
          </div>
        </div>
        <button type="submit" className="primary" disabled={loading}>
          {loading ? 'Checking…' : 'Check this message'}
        </button>
        <p className="privacy">Your message is only used to run this check. It is not saved.</p>
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
            {explainError && <p role="alert" className="error">{explainError}</p>}
            {explanation && (
              <div className="explanation" aria-live="polite">
                <p>{explanation.text}</p>
                <p className="source">
                  {explanation.source === 'claude' ? 'Written by AI (Claude). It can make mistakes.' : 'Built-in explanation.'}
                  {explanation.note ? ` ${explanation.note}` : ''}
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

      <footer>Scam Shield looks for common warning signs. It can be wrong. When in doubt, ask someone you trust.</footer>
    </main>
  )
}
