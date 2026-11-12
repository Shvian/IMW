import React, { useState } from 'react'
import { api } from '../api.js'
import { Card, Chip, Field, JobConsole, useAction, useLatestJob } from '../components.jsx'
import RunPanel from './RunPanel.jsx'

export default function Migrate({ ov, refresh, go }) {
  const [perTemplate, setPerTemplate] = useState(1)
  const [probeJob, setProbeJob] = useLatestJob(['probe-delinea'], ov.job)
  const [run, busy] = useAction()
  const running = ov.job && ov.job.state === 'running'
  const plan = ov.plan || {}
  const planClean = plan.exit_code === 0 && plan.review === ov.review_shas.review && plan.members === ov.review_shas.members
  const reh = ov.steps.find((s) => s.id === 'rehearsal')
  const checks = [
    { ok: planClean, text: 'A clean plan on the current review files', page: 'review', required: true },
    { ok: ov.session.credentials.cyberark, text: 'CyberArk client secret entered', page: 'connections', required: true },
    { ok: ov.session.credentials.delinea, text: 'Delinea credential entered (needed for the accounts stage)', page: 'connections', required: true },
    { ok: reh.status === 'done', text: 'Rehearsal completed without failures (recommended)', page: 'rehearsal' },
    { ok: !!(ov.steps.find((s) => s.id === 'readiness').status === 'done'), text: 'Server readiness checks pass (recommended)', page: 'readiness' },
  ]
  const blockers = checks.filter((c) => c.required && !c.ok).map((c) => c.text + ' is missing.')

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Migration</h1>
          <p className="muted">Creates the Safes, adds the members, then onboards each account. Each secret is read from Delinea at the moment it is sent to CyberArk, and is never stored.</p>
        </div>
      </div>

      <Card title="Go / no-go">
        <ul className="checklist">
          {checks.map((c, i) => (
            <li key={i} className={c.ok ? 'ok' : c.required ? 'missing' : 'optional'}>
              <span className="tick" aria-hidden="true">{c.ok ? '✓' : c.required ? '✗' : '–'}</span>
              <span>{c.text}</span>
              {!c.ok && <button className="btn ghost sm" onClick={() => go(c.page)}>Open</button>}
            </li>
          ))}
        </ul>
      </Card>

      <Card title="Delinea access probe (cutover day)" actions={
        <button className="btn" disabled={busy || running || !ov.session.credentials.delinea}
          onClick={() => run(async () => { const j = await api('jobs', { method: 'POST', body: { action: 'probe-delinea', options: { per_template: perTemplate } } }); setProbeJob(j.id) })}>
          Run probe
        </button>}>
        <p className="muted small">Reads a few secrets for each template and field to prove the API user can read them. Only the length is shown; values are never displayed or stored.</p>
        <Field label="Secrets per template"><input type="number" min="1" max="5" value={perTemplate} onChange={(e) => setPerTemplate(Number(e.target.value))} /></Field>
        <JobConsole jobId={probeJob} height={200} onFinished={() => refresh(false)} />
      </Card>

      <RunPanel ov={ov} refresh={refresh} mode="production" action="migrate" word="MIGRATE" blockers={blockers}
        summaryNote="This writes to the production tenant. Secrets are read from Delinea one at a time, just in time." />

      <div className="row end">
        <button className="btn ghost" onClick={() => go('results')}>Open results</button>
      </div>
    </div>
  )
}
