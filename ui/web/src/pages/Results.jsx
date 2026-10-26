import React, { useCallback, useEffect, useState } from 'react'
import { api, fmtTime } from '../api.js'
import { Card, Chip, Callout, FilesTable, JobConsole, Pager, useAction, useLatestJob } from '../components.jsx'

const LIMIT = 100

export default function Results({ ov, refresh }) {
  const [mode, setMode] = useState('production')
  const [tab, setTab] = useState('ledger')
  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Results</h1>
          <p className="muted">Everything that was done, what failed and why, and the tamper-evident audit trail.</p>
        </div>
        <div className="seg-control" role="radiogroup" aria-label="Ledger">
          {['production', 'rehearsal'].map((m) => (
            <button key={m} role="radio" aria-checked={mode === m} className={mode === m ? 'active' : ''} onClick={() => setMode(m)}>
              {m === 'production' ? 'Migration' : 'Rehearsal'}
            </button>
          ))}
        </div>
      </div>
      <Summary mode={mode} />
      <div className="tabs" role="tablist">
        {[['ledger', 'Objects'], ['runs', 'Runs'], ['audit', 'Audit log'], ['files', 'Reports and downloads']].map(([id, label]) => (
          <button key={id} role="tab" aria-selected={tab === id} className={'tab' + (tab === id ? ' active' : '')} onClick={() => setTab(id)}>{label}</button>
        ))}
      </div>
      {tab === 'ledger' && <Ledger mode={mode} />}
      {tab === 'runs' && <Runs mode={mode} />}
      {tab === 'audit' && <Audit mode={mode} />}
      {tab === 'files' && <Downloads mode={mode} ov={ov} refresh={refresh} />}
    </div>
  )
}

function Summary({ mode }) {
  const [p, setP] = useState(null)
  useEffect(() => { api('progress?mode=' + mode).then(setP).catch(() => {}) }, [mode])
  if (!p) return null
  if (!p.ledger) return <Callout title="No runs yet">Nothing has been run against this ledger.</Callout>
  const st = p.ledger.stages
  return (
    <div className="stats">
      {[['SAFE', 'Safes'], ['MEMBER', 'Members'], ['ACCOUNT', 'Accounts']].map(([k, label]) => {
        const s = st[k] || {}
        return (
          <div key={k} className="stat wide">
            <div className="stat-n">{s.DONE || 0}<span className="muted small"> / {Math.max(p.totals[k] || 0, Object.values(s).reduce((a, b) => a + b, 0))}</span></div>
            <div className="small">{label} done</div>
            <div className="small">{s.FAILED ? <span className="error-text">{s.FAILED} failed</span> : <span className="muted">0 failed</span>}{s.IN_PROGRESS ? ` · ${s.IN_PROGRESS} interrupted` : ''}{s.PENDING ? ` · ${s.PENDING} pending` : ''}</div>
          </div>
        )
      })}
      <div className="stat wide"><div className="stat-n">{p.ledger.runs}</div><div className="small">runs recorded</div></div>
    </div>
  )
}

function Ledger({ mode }) {
  const [stage, setStage] = useState('')
  const [status, setStatus] = useState('')
  const [q, setQ] = useState('')
  const [offset, setOffset] = useState(0)
  const [data, setData] = useState(null)
  const [open, setOpen] = useState(null)
  const load = useCallback(() => api(`ledger?mode=${mode}&stage=${stage}&status=${status}&q=${encodeURIComponent(q)}&offset=${offset}&limit=${LIMIT}`)
    .then(setData).catch(() => {}), [mode, stage, status, q, offset])
  useEffect(() => { const t = setTimeout(load, 200); return () => clearTimeout(t) }, [load])
  if (!data) return null
  return (
    <Card>
      <div className="toolbar">
        <select value={stage} onChange={(e) => { setStage(e.target.value); setOffset(0) }} aria-label="Stage">
          <option value="">All stages</option><option value="SAFE">Safes</option><option value="MEMBER">Members</option><option value="ACCOUNT">Accounts</option>
        </select>
        <select value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0) }} aria-label="Status">
          <option value="">Any status</option><option value="FAILED">Failed</option><option value="IN_PROGRESS">Interrupted</option><option value="DONE">Done</option><option value="PENDING">Pending</option>
        </select>
        <input className="search" placeholder="Safe, account, secret ID or error" value={q} onChange={(e) => { setQ(e.target.value); setOffset(0) }} aria-label="Search ledger" />
        <span className="spacer" />
        <button className="btn ghost sm" onClick={load}>Refresh</button>
      </div>
      {status === 'FAILED' && data.total > 0 && (
        <Callout kind="info" title="To retry">Fix the causes shown in the hints (in the review files or in CyberArk), then use <strong>Retry failed only</strong> on the Migration or Rehearsal page. Finished objects are never sent twice.</Callout>
      )}
      <table className="table">
        <thead><tr><th>Stage</th><th>Safe</th><th>Object</th><th>Status</th><th>Attempts</th><th>Error</th><th>Updated</th></tr></thead>
        <tbody>
          {data.rows.map((r) => (
            <React.Fragment key={r.obj_key}>
              <tr className={r.status === 'FAILED' ? 'flag' : ''} onClick={() => setOpen(open === r.obj_key ? null : r.obj_key)} style={{ cursor: 'pointer' }}>
                <td>{r.stage}</td>
                <td className="mono">{r.safe}</td>
                <td>{r.object}{r.delinea_secret_id ? <span className="muted small"> #{r.delinea_secret_id}</span> : ''}</td>
                <td><Chip status={r.status}>{r.status}{r.result ? ' / ' + r.result : ''}</Chip></td>
                <td>{r.attempts}</td>
                <td className="small">{r.last_error ? `${r.error_system || ''} ${r.http_status || ''} ${r.last_error}` : ''}</td>
                <td className="muted small">{fmtTime(r.updated)}</td>
              </tr>
              {open === r.obj_key && (
                <tr className="detail"><td colSpan={7}>
                  {r.hint && <div><strong>How to fix:</strong> {r.hint}</div>}
                  <div className="muted small mono">key {r.obj_key} · CyberArk ID {r.cyberark_id || '-'} · error code {r.error_code || '-'} · source line {r.source_line || '-'} · first seen {fmtTime(r.first_seen)} · last run {r.last_run_id || '-'}</div>
                </td></tr>
              )}
            </React.Fragment>
          ))}
          {!data.rows.length && <tr><td colSpan={7} className="muted">No objects match.</td></tr>}
        </tbody>
      </table>
      <Pager offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />
    </Card>
  )
}

function Runs({ mode }) {
  const [data, setData] = useState(null)
  useEffect(() => { api(`ledger?mode=${mode}&limit=1`).then(setData).catch(() => {}) }, [mode])
  if (!data) return null
  return (
    <Card>
      <table className="table">
        <thead><tr><th>Started</th><th>Finished</th><th>Outcome</th><th>Operator</th><th>Command</th><th>Review file SHA-256</th></tr></thead>
        <tbody>
          {(data.runs || []).map((r) => (
            <tr key={r.run_id}>
              <td>{fmtTime(r.started)}</td><td>{fmtTime(r.finished)}</td><td><Chip status={r.outcome}>{r.outcome}</Chip></td>
              <td>{r.operator}</td><td className="mono small wrapcell">{r.command}</td><td className="mono small">{(r.review_sha256 || '').slice(0, 16)}…</td>
            </tr>
          ))}
          {!(data.runs || []).length && <tr><td colSpan={6} className="muted">No runs yet.</td></tr>}
        </tbody>
      </table>
    </Card>
  )
}

function Audit({ mode }) {
  const [log, setLog] = useState(mode)
  const [offset, setOffset] = useState(0)
  const [data, setData] = useState(null)
  const [verify, setVerify] = useState(null)
  const [run, busy] = useAction()
  useEffect(() => { setLog(mode); setOffset(0); setVerify(null) }, [mode])
  useEffect(() => { api(`audit?log=${log}&offset=${offset}&limit=${LIMIT}`).then(setData).catch(() => {}) }, [log, offset])
  if (!data) return null
  const SKIP = new Set(['ts', 'run_id', 'operator', 'host', 'event', 'prev_hash', 'hash'])
  return (
    <Card>
      <div className="toolbar">
        <select value={log} onChange={(e) => { setLog(e.target.value); setOffset(0); setVerify(null) }} aria-label="Audit log">
          <option value="production">Migration audit log</option>
          <option value="rehearsal">Rehearsal audit log</option>
          <option value="ui">UI actions audit log</option>
        </select>
        <span className="spacer" />
        <button className="btn" disabled={busy || !data.file} onClick={() => run(async () => setVerify(await api('audit/verify', { method: 'POST', body: { log } })))}>Verify hash chain</button>
      </div>
      {verify && <Callout kind={verify.ok ? 'ok' : 'error'} title={verify.ok ? 'Audit log intact' : 'Audit log check FAILED'}>{verify.message}</Callout>}
      <p className="muted small">Newest first. Each entry includes the hash of the one before it, so any edit or deletion breaks the chain.</p>
      <table className="table compact">
        <thead><tr><th>Time</th><th>Event</th><th>Operator</th><th>Details</th></tr></thead>
        <tbody>
          {data.entries.map((e, i) => (
            <tr key={i} className={/fail|error/i.test(e.event) || e.outcome === 'FAILED' ? 'flag' : ''}>
              <td className="small">{fmtTime(e.ts)}</td>
              <td className="mono small">{e.event}</td>
              <td className="small">{e.operator_name ? `${e.operator_name} (${e.operator})` : e.operator}</td>
              <td className="mono small wrapcell">{JSON.stringify(Object.fromEntries(Object.entries(e).filter(([k]) => !SKIP.has(k) && k !== 'operator_name')))}</td>
            </tr>
          ))}
          {!data.entries.length && <tr><td colSpan={4} className="muted">No entries yet.</td></tr>}
        </tbody>
      </table>
      <Pager offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />
    </Card>
  )
}

function Downloads({ mode, ov, refresh }) {
  const [files, setFiles] = useState([])
  const [jobId, setJobId] = useLatestJob(['report', 'verify-audit'], ov.job)
  const [run, busy] = useAction()
  const load = () => api('files').then((r) => setFiles(r.files)).catch(() => {})
  useEffect(() => { load() }, [])
  const start = (action) => run(async () => { const j = await api('jobs', { method: 'POST', body: { action, options: { mode } } }); setJobId(j.id) })
  const running = ov.job && ov.job.state === 'running'
  return (
    <Card title="Reports and downloads" actions={<>
      <button className="btn" disabled={busy || running} onClick={() => start('report')}>Export ledger report (CSV)</button>
      <button className="btn ghost" disabled={busy || running} onClick={() => start('verify-audit')}>Verify audit log</button>
    </>}>
      <JobConsole jobId={jobId} height={140} onFinished={() => { load(); refresh(false) }} />
      <h3>{mode === 'production' ? 'Migration' : 'Rehearsal'} ledger, audit log and run logs</h3>
      <FilesTable files={files} areas={['state/' + mode]} />
      <h3>Review files, UI audit and readiness reports</h3>
      <FilesTable files={files} areas={['phase1_output', 'ui_audit.jsonl', 'readiness', 'state/preflight', 'history']} />
      <p className="muted small">Drag any file onto the desktop or a folder to save it (Edge and Chrome), or click to download. Downloads are recorded in the UI audit log.</p>
    </Card>
  )
}
