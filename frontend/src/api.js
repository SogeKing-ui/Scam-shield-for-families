// Small fetch helper. The browser sends the sign-in cookie automatically (same origin).
export async function api(path, { method = 'GET', body } = {}) {
  const hasBody = method !== 'GET' && method !== 'DELETE'
  const res = await fetch(path, {
    method,
    headers: hasBody ? { 'Content-Type': 'application/json' } : undefined,
    body: hasBody ? JSON.stringify(body || {}) : undefined,
    credentials: 'same-origin',
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const err = new Error(data.error || 'Something went wrong. Please try again.')
    err.status = res.status
    throw err
  }
  return data
}

export function friendlyError(err) {
  return err.message === 'Failed to fetch' ? 'Cannot reach the checker. Is the server running?' : err.message
}
