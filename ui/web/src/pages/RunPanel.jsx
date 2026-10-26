import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Card, Chip, Callout, ConfirmDialog, JobConsole, Progress, useAction, useLatestJob } from '../components.jsx'

// Shared run controls for the rehearsal and the real migration.
export default function RunPanel({ ov, refresh, mode, action, word, children, extraOptions = {}, blockers = [], summaryNote }) {
  const [safes, setSafes] = useState([])
  const [pilot, setPilot] = useState([])
  const [stages, setStages] = useState({ safes: true, members: true, accounts: true })
  const [confirm, setConfirm] = useState(null)        // {only_failed}
  const [forceUnlock, setForceUnlock] = useState(false)
  const [jobId, setJobId] = useLatestJob([action], ov.job)
  const [run, busy] = useAction()
  const running = !!(ov.job && ov.job.state === 'running')
  const mine = running && ov.job.action === action
  const locked = ov.locks[mode] && !running

  useEffect(() => { api('review/safes').then((r) => setSafes(r.safes.map((s) => s.safe))).catch(() => {}) }, [])

  const start = (only_failed) => run(async () => {
    const options = { ...extraOptions, only_failed, safes: pilot, force_unlock: forceUnlock,
      stages: Object.keys(stages).filter((k) => stages[k]) }
    const j = await api('jobs', { method: 'POST', body: { action, options, confirm: word } })
    setJobId(j.id); setConfirm(null); setForceUnlock(false); refresh(false)
  })

  return (
    <>
      {children}
      <Card title="Run">
        {blockers.length > 0 && (
          <Callout kind="warn" title="Before you start">
            <ul className="bullets">{blockers.map((b, i) => <li key={i}>{b}</li>)}</ul>
          </Callout>
        )}
        {locked && (
          <Callout kind="warn" title="A run lock was left behind">
            A previous run stopped without releasing its lock (for example after a crash or a forced stop). If no other run is active, clear it with the next start.
            <label className="check"><input type="checkbox" checked={forceUnlock} onChange={(e) => setForceUnlock(e.target.checked)} /> Clear the stale lock when starting</label>
          </Callout>
        )}
        <div className="grid2">
          <div>
            <h3>Stages</h3>
            {['safes', 'members', 'accounts'].map((s) => (
              <label key={s} className="check"><input type="checkbox" checked={stages[s]} onChange={(e) => setStages({ ...stages, [s]: e.target.checked })} /> {s[0].toUpperCase() + s.slice(1)}</label>
            ))}
            <p className="muted small">Always in this order. Finished objects are skipped on every run.</p>
          </div>
          <div>
            <h3>Pilot (optional)</h3>
            <select multiple size={6} value={pilot} onChange={(e) => setPilot([...e.target.selectedOptions].map((o) => o.value))} aria-label="Pilot Safes" className="multi">
              {safes.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <p className="muted small">{pilot.length ? `Only ${pilot.length} Safe(s): ${pilot.join(', ')}` : 'No Safe selected means all Safes. Ctrl+click to choose a few for a pilot.'}</p>
          </div>
        </div>
        <div className="row gap end">
          <button className="btn" disabled={busy || running || blockers.length > 0} onClick={() => setConfirm({ only_failed: true })}>Retry failed only</button>
          <button className="btn primary" disabled={busy || running || blockers.length > 0} onClick={() => setConfirm({ only_failed: false })}>
            {action === 'rehearsal' ? 'Start rehearsal' : 'Start migration'}
          </button>
        </div>
      </Card>

      <Card title="Progress" actions={mine && <Chip status="running">Running</Chip>}>
        <Progress mode={mode} running={mine} />
        <JobConsole jobId={jobId} height={360} onFinished={() => refresh(false)} />
      </Card>

      <ConfirmDialog open={!!confirm} title={action === 'rehearsal' ? 'Start the rehearsal' : 'Start the migration'} word={word}
        danger={action === 'migrate'} confirmLabel={confirm && confirm.only_failed ? 'Retry failed' : 'Start'}
        onCancel={() => setConfirm(null)} onConfirm={() => start(confirm.only_failed)}>
        <ul className="bullets">
          <li>{confirm && confirm.only_failed ? 'Only objects that failed or were interrupted are retried.' : 'Everything not yet done is processed. Done objects are skipped.'}</li>
          <li>Stages: {Object.keys(stages).filter((k) => stages[k]).join(', ')}</li>
          <li>{pilot.length ? `Pilot: ${pilot.join(', ')}` : 'All Safes in the review file'}</li>
          {summaryNote && <li>{summaryNote}</li>}
          <li>Recorded in the audit log as {ov.session.operator ? `${ov.session.operator} (${ov.os_user})` : ov.os_user}.</li>
        </ul>
      </ConfirmDialog>
    </>
  )
}
