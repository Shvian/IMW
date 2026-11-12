import React, { useState } from 'react'
import { api } from '../api.js'
import { Card, Callout, ConfirmDialog, Field, JobConsole, useAction, useLatestJob } from '../components.jsx'
import RunPanel from './RunPanel.jsx'

export default function Rehearsal({ ov, refresh }) {
  const [prefix, setPrefix] = useState('ZZTEST-')
  const [cleanup, setCleanup] = useState(false)
  const [cleanJob, setCleanJob] = useLatestJob(['cleanup-rehearsal'], ov.job)
  const [run, busy] = useAction()
  const running = ov.job && ov.job.state === 'running'
  const blockers = []
  if (!ov.session.credentials.cyberark) blockers.push('Enter the CyberArk client secret under Connections.')
  if (ov.steps.find((s) => s.id === 'mapping').status === 'todo') blockers.push('Generate the mapping first.')
  if (!/^ZZ[A-Za-z0-9-]{0,10}$/i.test(prefix)) blockers.push('The prefix must start with ZZ, e.g. ZZTEST-.')

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Rehearsal</h1>
          <p className="muted">A full write test in the real tenant, using test Safes and random fake secrets. Delinea is never contacted, so this works before you have Delinea access.</p>
        </div>
      </div>
      <RunPanel ov={ov} refresh={refresh} mode="rehearsal" action="rehearsal" word="REHEARSE" blockers={blockers}
        extraOptions={{ prefix }} summaryNote={`Safes are created as ${prefix}<name>, with fake secrets, in a separate rehearsal ledger.`}>
        <Card title="Test Safes">
          <Field label="Safe prefix" hint="Must start with ZZ so test Safes are never mistaken for real ones. Names are cut to 28 characters after the prefix.">
            <input value={prefix} onChange={(e) => setPrefix(e.target.value)} />
          </Field>
          <Callout title="What the rehearsal proves">
            Sign-in and token renewal, API rights, Safe creation, that every member group can be found in the directory, platforms, account onboarding, rate-limit behaviour and the retry path. It does not prove Delinea access. Use the Delinea probe on the Migration page for that on cutover day.
          </Callout>
        </Card>
      </RunPanel>

      <Card title="Clean up" actions={
        <button className="btn danger" disabled={busy || running || !ov.session.credentials.cyberark} onClick={() => setCleanup(true)}>Delete rehearsal Safes</button>}>
        <p className="muted small">Deletes only the Safes this rehearsal created (and their accounts), as recorded in the rehearsal ledger. Safes that already existed are never touched.</p>
        <JobConsole jobId={cleanJob} height={220} onFinished={() => refresh(false)} />
      </Card>

      <ConfirmDialog open={cleanup} title="Delete the rehearsal Safes" word="DELETE" danger confirmLabel="Delete"
        onCancel={() => setCleanup(false)}
        onConfirm={() => run(async () => {
          const j = await api('jobs', { method: 'POST', body: { action: 'cleanup-rehearsal', confirm: 'DELETE', options: { force_unlock: ov.locks.rehearsal } } })
          setCleanJob(j.id); setCleanup(false); refresh(false)
        })}>
        <p>Every account in, and then every Safe created by, this rehearsal is deleted from the tenant. The list is printed in the output before deletion.</p>
      </ConfirmDialog>
    </div>
  )
}
