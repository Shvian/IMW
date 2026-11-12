import React from 'react'
import { Card, Chip } from '../components.jsx'

const STATUS_TEXT = { done: 'Done', warn: 'Needs attention', todo: 'To do' }

export default function Overview({ ov, go }) {
  const steps = ov.steps
  const next = steps.find((s) => s.status !== 'done' && s.id !== 'rehearsal') || steps.find((s) => s.status !== 'done')
  return (
    <div className="stack">
      <div className="hero">
        <h1>Delinea → CyberArk migration</h1>
        <p className="muted">
          Work through the stages in order. Each stage runs the same tools as the command line, so the ledger,
          audit logs and the resume without duplicates work the same way.
        </p>
        {next && (
          <button className="btn primary" onClick={() => go(next.id)}>
            Next: {next.title}
          </button>
        )}
      </div>

      <div className="steps">
        {steps.map((s, i) => (
          <button key={s.id} className={'step-card ' + s.status} onClick={() => go(s.id)}>
            <div className="row between">
              <span className="step-num">{i + 1}</span>
              <Chip status={s.status}>{STATUS_TEXT[s.status] || s.status}</Chip>
            </div>
            <div className="step-title">{s.title}</div>
            <div className="muted small">{s.detail}</div>
          </button>
        ))}
      </div>

      <Card title="How this console keeps the data safe">
        <ul className="bullets">
          <li><strong>Only on this server.</strong> It listens on 127.0.0.1, opens only from the one-time link in its console window, and ends the session after inactivity.</li>
          <li><strong>Credentials stay in memory.</strong> The API credentials you enter are kept in the server process only. They are never written to disk or logs and never sent back to the browser. They go only to the migration step that needs them.</li>
          <li><strong>No secret values in files.</strong> Uploaded CSVs are scrubbed before saving: password and private key columns, and attachments, are removed. The migration reads each secret from Delinea at the moment it is sent to CyberArk.</li>
          <li><strong>Everything is audited.</strong> UI actions, edits, uploads, downloads and runs are written to hash-chained audit logs. You can verify them under Results.</li>
        </ul>
      </Card>
    </div>
  )
}
