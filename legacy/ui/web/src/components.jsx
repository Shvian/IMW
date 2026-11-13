import React, { useEffect, useRef, useState, useCallback, createContext, useContext } from 'react'
import { api, downloadUrl, fmtBytes, fmtTime } from './api.js'

// ---------------------------------------------------------------- toasts
const ToastCtx = createContext(() => {})
export const useToast = () => useContext(ToastCtx)

export function ToastHost({ children }) {
  const [items, setItems] = useState([])
  const push = useCallback((msg, kind = 'info', hint) => {
    const id = Math.random().toString(36).slice(2)
    setItems((xs) => [...xs, { id, msg, kind, hint }])
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), kind === 'error' ? 12000 : 5000)
  }, [])
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={'toast ' + t.kind} onClick={() => setItems((xs) => xs.filter((x) => x.id !== t.id))}>
            <div>{t.msg}</div>
            {t.hint && <div className="muted small">{t.hint}</div>}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  )
}

// Wraps an async action: shows errors as toasts, tracks busy state.
export function useAction() {
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const run = useCallback(async (fn, okMsg) => {
    setBusy(true)
    try {
      const r = await fn()
      if (okMsg) toast(typeof okMsg === 'function' ? okMsg(r) : okMsg, 'ok')
      return r
    } catch (e) {
      toast(e.message, 'error', e.hint)
      return undefined
    } finally {
      setBusy(false)
    }
  }, [toast])
  return [run, busy]
}

// ---------------------------------------------------------------- small pieces
export const Chip = ({ status, children }) => (
  <span className={'chip ' + String(status || '').toLowerCase().replace(/[^a-z_]/g, '')}>{children || status}</span>
)

export function Card({ title, actions, children, className = '' }) {
  return (
    <section className={'card ' + className}>
      {(title || actions) && (
        <header className="card-head">
          {title && <h2>{title}</h2>}
          {actions && <div className="row gap">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  )
}

export function Callout({ kind = 'info', title, children }) {
  return (
    <div className={'callout ' + kind}>
      {title && <strong>{title}</strong>}
      <div>{children}</div>
    </div>
  )
}

export function Field({ label, hint, children }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  )
}

export function Pager({ offset, limit, total, onChange }) {
  if (total <= limit) return <span className="muted small">{total} rows</span>
  const page = Math.floor(offset / limit) + 1
  const pages = Math.ceil(total / limit)
  return (
    <div className="row gap small">
      <button className="btn ghost sm" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>Previous</button>
      <span className="muted">Page {page} of {pages} ({total} rows)</span>
      <button className="btn ghost sm" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>Next</button>
    </div>
  )
}

// ---------------------------------------------------------------- confirm dialog
export function ConfirmDialog({ open, title, word, danger, children, onConfirm, onCancel, confirmLabel }) {
  const [typed, setTyped] = useState('')
  useEffect(() => { if (open) setTyped('') }, [open])
  if (!open) return null
  const ok = !word || typed.trim() === word
  return (
    <div className="modal-back" onMouseDown={onCancel}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} onMouseDown={(e) => e.stopPropagation()}>
        <h2>{title}</h2>
        <div className="modal-body">{children}</div>
        {word && (
          <Field label={<>Type <code>{word}</code> to confirm</>}>
            <input autoFocus value={typed} onChange={(e) => setTyped(e.target.value)} aria-label={'Type ' + word}
              onKeyDown={(e) => { if (e.key === 'Enter' && ok) onConfirm(typed.trim()) }} />
          </Field>
        )}
        <div className="row gap end">
          <button className="btn ghost" onClick={onCancel}>Cancel</button>
          <button className={'btn ' + (danger ? 'danger' : 'primary')} disabled={!ok} onClick={() => onConfirm(typed.trim())}>
            {confirmLabel || 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------- drop zone
export function DropZone({ label, hint, accept = '.csv', onFile, busy }) {
  const [over, setOver] = useState(false)
  const input = useRef(null)
  const pick = (files) => { if (files && files[0]) onFile(files[0]) }
  return (
    <div
      className={'dropzone' + (over ? ' over' : '') + (busy ? ' busy' : '')}
      onDragOver={(e) => { e.preventDefault(); setOver(true) }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => { e.preventDefault(); setOver(false); pick(e.dataTransfer.files) }}
      onClick={() => input.current && input.current.click()}
      role="button" tabIndex={0}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') input.current.click() }}
    >
      <input ref={input} type="file" accept={accept} hidden onChange={(e) => { pick(e.target.files); e.target.value = '' }} />
      <div className="dz-icon" aria-hidden="true">⇪</div>
      <div className="dz-label">{busy ? 'Scrubbing and saving…' : label}</div>
      <div className="muted small">{hint || 'Drop a CSV here, or click to choose one'}</div>
    </div>
  )
}

// ---------------------------------------------------------------- files list (drag out to the desktop)
export function FileLink({ path, label }) {
  const url = downloadUrl(path)
  const name = path.split('/').pop()
  const onDragStart = (e) => {
    // Chromium browsers (Edge, Chrome) save the file when it is dropped on the desktop or a folder.
    const abs = new URL(url, window.location.href).href
    e.dataTransfer.setData('DownloadURL', `application/octet-stream:${name}:${abs}`)
  }
  return (
    <a href={url} download={name} draggable onDragStart={onDragStart} className="filelink" title="Click to download, or drag to a folder">
      {label || name}
    </a>
  )
}

export function FilesTable({ files, areas, empty = 'No files yet' }) {
  const list = files.filter((f) => !areas || areas.some((a) => f.area === a || f.path.startsWith(a + '/')))
  if (!list.length) return <p className="muted">{empty}</p>
  return (
    <table className="table compact">
      <thead><tr><th>File</th><th>Folder</th><th>Size</th><th>Modified</th></tr></thead>
      <tbody>
        {list.map((f) => (
          <tr key={f.path}>
            <td><FileLink path={f.path} /></td>
            <td className="muted">{f.path.split('/').slice(0, -1).join('/')}</td>
            <td>{fmtBytes(f.size)}</td>
            <td className="muted">{fmtTime(f.modified)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

// ---------------------------------------------------------------- jobs
// Finds the most recent job for the given actions so a page shows its last output after a revisit.
export function useLatestJob(actions, overviewJob) {
  const [jobId, setJobId] = useState(null)
  const key = actions.join(',')
  useEffect(() => {
    let live = true
    api('jobs', { poll: true }).then((r) => {
      const j = (r.history || []).find((x) => actions.includes(x.action))
      if (live && j) setJobId(j.id)
    }).catch(() => {})
    return () => { live = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])
  useEffect(() => {
    if (overviewJob && actions.includes(overviewJob.action)) setJobId(overviewJob.id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [overviewJob && overviewJob.id, key])
  return [jobId, setJobId]
}

const OUTCOME_TEXT = {
  ok: 'Finished', failures: 'Finished with failures', invalid: 'Stopped: input problems', error: 'Failed',
  stopped: 'Stopped', running: 'Running',
}

export function JobConsole({ jobId, onFinished, title = 'Output', height = 320 }) {
  const [job, setJob] = useState(null)
  const [lines, setLines] = useState([])
  const since = useRef(0)
  const box = useRef(null)
  const stick = useRef(true)
  const finishedFor = useRef(null)
  const [run] = useAction()

  useEffect(() => {
    setLines([]); setJob(null); since.current = 0
    if (!jobId) return
    let live = true
    let timer
    const tick = async () => {
      try {
        const r = await api(`jobs/${jobId}/output?since=${since.current}`, { poll: true })
        if (!live) return
        if (r.lines.length) {
          setLines((xs) => {
            const next = xs.concat(r.lines)
            return next.length > 5000 ? next.slice(next.length - 5000) : next
          })
        }
        since.current = r.from + r.lines.length
        setJob(r.job)
        if (r.job.state === 'running' || r.lines.length === 2000) {
          timer = setTimeout(tick, 800)
        } else if (finishedFor.current !== jobId) {
          finishedFor.current = jobId
          onFinished && onFinished(r.job)
        }
      } catch (e) {
        if (live) timer = setTimeout(tick, 3000)
      }
    }
    tick()
    return () => { live = false; clearTimeout(timer) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId])

  useEffect(() => {
    if (stick.current && box.current) box.current.scrollTop = box.current.scrollHeight
  }, [lines])

  if (!jobId) return null
  const onScroll = () => {
    const el = box.current
    stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40
  }
  return (
    <div className="console">
      <div className="console-head">
        <strong>{job ? job.label : title}</strong>
        {job && <Chip status={job.outcome}>{OUTCOME_TEXT[job.outcome] || job.outcome}{job.exit_code != null ? ` (exit ${job.exit_code})` : ''}</Chip>}
        <span className="spacer" />
        {job && job.state === 'running' && (
          <button className="btn danger sm" onClick={() => run(() => api('jobs/current/stop', { method: 'POST' }), 'Stop requested. Finished work is kept; in-progress items are re-checked next run.')}>
            Stop
          </button>
        )}
      </div>
      <pre ref={box} onScroll={onScroll} style={{ height }} tabIndex={0} aria-label="Job output">
        {lines.map((l, i) => <div key={i} className={lineClass(l)}>{l || ' '}</div>)}
        {job && job.state === 'running' && <div className="cursor">▍</div>}
      </pre>
    </div>
  )
}

function lineClass(l) {
  if (/\b(ERROR|FAIL|FAILED|BLOCKER)\b/.test(l)) return 'ln-err'
  if (/\b(WARN|WARNING|UNVERIFIED)\b/.test(l)) return 'ln-warn'
  if (/\b(OK|PASS|CREATED|DONE)\b/.test(l)) return 'ln-ok'
  return ''
}

// ---------------------------------------------------------------- progress bars from the ledger
const STAGES = [['SAFE', 'Safes'], ['MEMBER', 'Safe members'], ['ACCOUNT', 'Accounts']]

export function Progress({ mode, running }) {
  const [p, setP] = useState(null)
  useEffect(() => {
    let live = true
    let timer
    const tick = async () => {
      try {
        const r = await api('progress?mode=' + mode, { poll: true })
        if (live) setP(r)
      } catch (e) { /* shown elsewhere */ }
      if (live && running) timer = setTimeout(tick, 1500)
    }
    tick()
    return () => { live = false; clearTimeout(timer) }
  }, [mode, running])
  if (!p) return null
  const led = (p.ledger && p.ledger.stages) || {}
  return (
    <div className="progress-grid">
      {STAGES.map(([k, label]) => {
        const s = led[k] || {}
        const total = Math.max(p.totals[k] || 0, (s.DONE || 0) + (s.FAILED || 0) + (s.IN_PROGRESS || 0) + (s.PENDING || 0))
        const pct = (n) => (total ? (100 * n) / total : 0)
        const cur = p.current_run && p.current_run.stages[k]
        return (
          <div key={k} className="progress-item">
            <div className="row between">
              <strong>{label}</strong>
              <span className="muted small">{s.DONE || 0} of {total} done{s.FAILED ? `, ${s.FAILED} failed` : ''}</span>
            </div>
            <div className="bar" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={total} aria-valuenow={s.DONE || 0}>
              <span className="seg done" style={{ width: pct(s.DONE || 0) + '%' }} />
              <span className="seg failed" style={{ width: pct(s.FAILED || 0) + '%' }} />
              <span className="seg active" style={{ width: pct(s.IN_PROGRESS || 0) + '%' }} />
            </div>
            {cur && <div className="muted small">This run: {Object.entries(cur).map(([st, n]) => `${n} ${st.toLowerCase()}`).join(', ')}</div>}
          </div>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------- simple key/value editor
export function KeyValueEditor({ value, onChange, keyLabel, valueLabel, keyPlaceholder, valuePlaceholder, options }) {
  const entries = Object.entries(value || {})
  const set = (i, k, v) => {
    const next = entries.map((e, j) => (j === i ? [k, v] : e))
    onChange(Object.fromEntries(next))
  }
  return (
    <table className="table compact kv">
      <thead><tr><th>{keyLabel}</th><th>{valueLabel}</th><th /></tr></thead>
      <tbody>
        {entries.map(([k, v], i) => (
          <tr key={i}>
            <td><input value={k} placeholder={keyPlaceholder} onChange={(e) => set(i, e.target.value, v)} aria-label={keyLabel} /></td>
            <td>
              {options ? (
                <select value={v} onChange={(e) => set(i, k, e.target.value)} aria-label={valueLabel}>
                  {options.map((o) => <option key={o}>{o}</option>)}
                </select>
              ) : (
                <input value={v} placeholder={valuePlaceholder} onChange={(e) => set(i, k, e.target.value)} aria-label={valueLabel} />
              )}
            </td>
            <td><button className="btn ghost sm" onClick={() => onChange(Object.fromEntries(entries.filter((_, j) => j !== i)))} aria-label="Remove">✕</button></td>
          </tr>
        ))}
        <tr>
          <td colSpan={3}>
            <button className="btn ghost sm" onClick={() => onChange({ ...Object.fromEntries(entries), '': options ? options[0] : '' })}>+ Add</button>
          </td>
        </tr>
      </tbody>
    </table>
  )
}

export function JsonEditor({ value, onApply }) {
  const [text, setText] = useState(() => JSON.stringify(value, null, 2))
  const [err, setErr] = useState('')
  useEffect(() => { setText(JSON.stringify(value, null, 2)) }, [value])
  return (
    <div>
      <textarea className="mono" rows={18} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} aria-label="JSON" />
      {err && <div className="error-text">{err}</div>}
      <button className="btn ghost sm" onClick={() => {
        try { onApply(JSON.parse(text)); setErr('') } catch (e) { setErr('Not valid JSON: ' + e.message) }
      }}>Apply JSON to the form</button>
    </div>
  )
}
