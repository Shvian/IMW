// Thin client for the local backend. Every call carries the X-Migration-UI header,
// which the server requires on anything that changes state (blocks cross-site forgery).
// Background refreshes send X-Poll so they do not keep an idle session alive.

export class ApiError extends Error {
  constructor(message, status, hint) {
    super(message)
    this.status = status
    this.hint = hint
  }
}

export async function api(path, { method = 'GET', body, poll = false, file } = {}) {
  const headers = { 'X-Migration-UI': '1' }
  if (poll) headers['X-Poll'] = '1'
  let payload
  if (file) {
    payload = file
    headers['Content-Type'] = 'application/octet-stream'
    headers['X-Filename'] = encodeURIComponent(file.name)
  } else if (body !== undefined) {
    payload = JSON.stringify(body)
    headers['Content-Type'] = 'application/json'
  }
  let r
  try {
    r = await fetch('/api/' + path, { method, headers, body: payload, credentials: 'same-origin' })
  } catch (e) {
    throw new ApiError('The migration UI server is not reachable. Is its console window still open?', 0)
  }
  const data = await r.json().catch(() => ({}))
  if (r.status === 401) window.dispatchEvent(new Event('session-ended'))
  if (!r.ok) throw new ApiError(data.error || r.statusText, r.status, data.hint)
  return data
}

export const downloadUrl = (path) => '/api/download?path=' + encodeURIComponent(path)

export function fmtBytes(n) {
  if (n < 1024) return n + ' B'
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB'
  return (n / 1024 / 1024).toFixed(1) + ' MB'
}

export function fmtTime(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return isNaN(d) ? iso : d.toLocaleString()
}
