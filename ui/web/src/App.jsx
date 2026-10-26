import React, { useCallback, useEffect, useState } from 'react'
import { api } from './api.js'
import { ToastHost, useAction, Chip, ConfirmDialog } from './components.jsx'
import Overview from './pages/Overview.jsx'
import Readiness from './pages/Readiness.jsx'
import Connections from './pages/Connections.jsx'
import Files from './pages/Files.jsx'
import Mapping from './pages/Mapping.jsx'
import Review from './pages/Review.jsx'
import Rehearsal from './pages/Rehearsal.jsx'
import Migrate from './pages/Migrate.jsx'
import Results from './pages/Results.jsx'

export const PAGES = [
  { id: 'overview', title: 'Overview', component: Overview },
  { id: 'readiness', title: 'Server readiness', component: Readiness, step: 1 },
  { id: 'connections', title: 'Connections', component: Connections, step: 2 },
  { id: 'files', title: 'Data files', component: Files, step: 3 },
  { id: 'mapping', title: 'Mapping rules', component: Mapping, step: 4 },
  { id: 'review', title: 'Review', component: Review, step: 5 },
  { id: 'rehearsal', title: 'Rehearsal', component: Rehearsal, step: 6 },
  { id: 'migrate', title: 'Migration', component: Migrate, step: 7 },
  { id: 'results', title: 'Results', component: Results, step: 8 },
]

const pageFromHash = () => {
  const id = window.location.hash.replace(/^#\/?/, '').split('?')[0]
  return PAGES.some((p) => p.id === id) ? id : 'overview'
}

function Shell() {
  const [page, setPage] = useState(pageFromHash)
  const [ov, setOv] = useState(null)
  const [ended, setEnded] = useState(false)
  const [loadErr, setLoadErr] = useState('')
  const [confirmStop, setConfirmStop] = useState(false)
  const [stopped, setStopped] = useState(false)
  const [run] = useAction()

  const refresh = useCallback(async (poll = true) => {
    try {
      const r = await api('overview', { poll })
      setOv(r)
      setLoadErr('')
      return r
    } catch (e) {
      if (e.status !== 401) setLoadErr(e.message)
      return null
    }
  }, [])

  useEffect(() => {
    refresh(false)
    const t = setInterval(() => refresh(true), 3000)
    const onEnd = () => setEnded(true)
    const onHash = () => setPage(pageFromHash())
    window.addEventListener('session-ended', onEnd)
    window.addEventListener('hashchange', onHash)
    return () => { clearInterval(t); window.removeEventListener('session-ended', onEnd); window.removeEventListener('hashchange', onHash) }
  }, [refresh])

  const go = (id) => { window.location.hash = '/' + id; setPage(id); window.scrollTo(0, 0) }

  if (stopped) {
    return <div className="ended"><h1>Migration UI stopped</h1><p>Credentials held in memory are gone. Start it again with <code>start-ui.cmd</code>.</p></div>
  }
  if (ended) {
    return (
      <div className="ended">
        <h1>Session ended</h1>
        <p>The session ended (inactivity, a new link was opened, or you ended it). Credentials held for it were dropped.</p>
        <p>Go to the console window where the UI is running and press <kbd>Enter</kbd> for a fresh one-time link.</p>
      </div>
    )
  }
  if (!ov) return <div className="ended"><p>{loadErr || 'Loading…'}</p></div>

  const stepStatus = Object.fromEntries(ov.steps.map((s) => [s.id, s.status]))
  const Page = PAGES.find((p) => p.id === page).component
  const idleMin = Math.ceil(ov.session.idle_left / 60)

  return (
    <div className="app">
      <aside className="nav">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">D→C</div>
          <div>
            <div className="brand-title">Migration Console</div>
            <div className="muted small">Delinea → CyberArk Privilege Cloud</div>
          </div>
        </div>
        <nav aria-label="Migration stages">
          {PAGES.map((p) => (
            <button key={p.id} className={'nav-item' + (p.id === page ? ' active' : '')} onClick={() => go(p.id)}
              aria-current={p.id === page ? 'page' : undefined}>
              <span className={'nav-dot ' + (stepStatus[p.id] || (p.id === 'overview' ? 'home' : 'todo'))}>{p.step || '•'}</span>
              <span>{p.title}</span>
            </button>
          ))}
        </nav>
        <div className="nav-foot muted small">
          <div>{ov.os_user} on {ov.host}</div>
          <div title={ov.workspace} className="ellipsis">Workspace: {ov.workspace}</div>
          <div>v{ov.version} · localhost only</div>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="row gap wrap">
            <OperatorName value={ov.session.operator} onSaved={() => refresh(false)} />
            <span className="cred-pill" title="Held in this server's memory only. Never saved to disk.">
              CyberArk <Chip status={ov.session.credentials.cyberark ? 'ok' : 'todo'}>{ov.session.credentials.cyberark ? 'credential set' : 'no credential'}</Chip>
            </span>
            <span className="cred-pill" title="Held in this server's memory only. Never saved to disk.">
              Delinea <Chip status={ov.session.credentials.delinea ? 'ok' : 'todo'}>{ov.session.credentials.delinea ? 'credential set' : 'no credential'}</Chip>
            </span>
          </div>
          <div className="row gap">
            <span className="muted small" title="The session ends, and credentials are dropped, after this much inactivity">
              Session: {idleMin} min left
            </span>
            <button className="btn ghost sm" onClick={() => run(async () => { await api('session', { method: 'DELETE' }); setEnded(true) })}>
              End session
            </button>
            <button className="btn ghost sm" onClick={() => setConfirmStop(true)}>Shut down</button>
          </div>
        </header>

        {ov.job && ov.job.state === 'running' && (
          <div className="jobbar">
            <span className="pulse" aria-hidden="true" /> <strong>{ov.job.label}</strong> is running.
            <span className="spacer" />
            {ov.job.action === 'migrate' && page !== 'migrate' && <button className="btn ghost sm" onClick={() => go('migrate')}>View progress</button>}
            {ov.job.action === 'rehearsal' && page !== 'rehearsal' && <button className="btn ghost sm" onClick={() => go('rehearsal')}>View progress</button>}
          </div>
        )}

        <main className="content">
          <Page ov={ov} refresh={refresh} go={go} />
        </main>
      </div>

      <ConfirmDialog open={confirmStop} title="Shut down the migration UI?" confirmLabel="Shut down" onCancel={() => setConfirmStop(false)}
        onConfirm={() => run(async () => { await api('shutdown', { method: 'POST' }); setStopped(true) })}>
        <p>This stops the local server and drops the credentials held in memory. Files, ledgers and audit logs stay in the workspace.</p>
      </ConfirmDialog>
    </div>
  )
}

function OperatorName({ value, onSaved }) {
  const [v, setV] = useState(value)
  const [run] = useAction()
  useEffect(() => setV(value), [value])
  const save = () => { if (v !== value) run(() => api('session', { method: 'PUT', body: { operator: v } }).then(onSaved), 'Name recorded for the audit log') }
  return (
    <label className="operator">
      <span className="muted small">Operator</span>
      <input value={v} placeholder="Your name (for the audit log)" onChange={(e) => setV(e.target.value)} onBlur={save}
        onKeyDown={(e) => e.key === 'Enter' && e.target.blur()} aria-label="Operator name" />
    </label>
  )
}

export default function App() {
  return <ToastHost><Shell /></ToastHost>
}
