// Verdict signs. The shape differs as well as the color, so the meaning never depends on color alone:
// a stop sign (scam), a warning triangle (be careful), and a check mark in a circle (no strong warning signs).
export function Sign({ level }) {
  if (level === 'high') {
    return (
      <svg className="sign" viewBox="0 0 64 64" aria-hidden="true" focusable="false">
        <polygon className="ring" points="21,3 43,3 61,21 61,43 43,61 21,61 3,43 3,21" />
        <polygon points="23,8 41,8 56,23 56,41 41,56 23,56 8,41 8,23" fill="currentColor" />
        <path className="mk" d="M24 24l16 16M40 24L24 40" strokeWidth="6" strokeLinecap="round" fill="none" />
      </svg>
    )
  }
  if (level === 'medium') {
    return (
      <svg className="sign" viewBox="0 0 64 64" aria-hidden="true" focusable="false">
        <path d="M32 5L61 56H3z" fill="currentColor" stroke="currentColor" strokeWidth="6" strokeLinejoin="round" />
        <path className="mk" d="M32 22v17" strokeWidth="6" strokeLinecap="round" fill="none" />
        <circle className="mkf" cx="32" cy="47" r="3.6" />
      </svg>
    )
  }
  return (
    <svg className="sign" viewBox="0 0 64 64" aria-hidden="true" focusable="false">
      <circle cx="32" cy="32" r="28" fill="currentColor" />
      <path className="mk" d="M19 33l9 9 17-19" fill="none" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export function Tick() {
  return (
    <svg className="tick" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d="M5 12.5l4.5 4.5L19 7.5" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export function ShieldMark() {
  return (
    <svg className="mark" viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <path d="M16 2.5l11 4v8.2c0 7-4.6 12.2-11 14.8C9.6 26.9 5 21.7 5 14.7V6.5z" fill="currentColor" />
      <path className="mk" d="M10.5 15.5l4 4 7-8" fill="none" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
