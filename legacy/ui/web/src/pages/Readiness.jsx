import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../api.js'
import { Card, Chip, Callout, JobConsole, useAction, useLatestJob, FileLink } from '../components.jsx'

const CATS = ['Software', 'Connectivity', 'Permissions', 'Security']

export default function Readiness({ ov, refresh }) {
  const [data, setData] = useState(null)
  const [sel, setSel] = useState({})
  const [open, setOpen] = useState({})
  const [elevated, setElevated] = useState(true)
  const [jobId, setJobId] = useLatestJob(['readiness', 'readiness-fix'], ov.job)
  const [run, busy] = useAction()
  const running = ov.job && ov.job.state === 'running'

  const load = () => api('readiness').then(setData).catch(() => {})
  useEffect(() => { load() }, [])

  const checks = (data && data.latest && data.latest.checks) || []
  const counts = useMemo(() => checks.reduce((a, c) => ({ ...a, [c.Status]: (a[c.Status] || 0) + 1 }), {}), [checks])
  const fixable = checks.filter((c) => c.AutoFix && (c.Status === 'Fail' || c.Status === 'Warn'))
  const selected = Object.keys(sel).filter((k) => sel[k])

  const start = (action, options) => run(async () => {
    const j = await api('jobs', { method: 'POST', body: { action, options } })
    setJobId(j.id)
    refresh(false)
  })

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Server readiness</h1>
          <p className="muted">Checks this server for software, connectivity, permissions and CIS-aligned hardening, then fixes what can be fixed safely.</p>
        </div>
        <button className="btn primary" disabled={busy || running || (data && !data.powershell)} onClick={() => start('readiness', {})}>
          Run checks
        </button>
      </div>

      {data && !data.powershell && (
        <Callout kind="warn" title="PowerShell is not available here">
          The readiness checks run on the Windows migration server. Start this UI there to use them.
        </Callout>
      )}

      {data && data.latest ? (
        <>
          <div className="stats">
            <Stat label="Passed" n={counts.Pass || 0} kind="ok" />
            <Stat label="Warnings" n={counts.Warn || 0} kind="warn" />
            <Stat label="Failed" n={counts.Fail || 0} kind="failed" />
            <Stat label="Auto-fixable" n={fixable.length} kind="info" />
          </div>
          <p className="muted small">
            Last run {data.latest.generated && new Date(data.latest.generated).toLocaleString()} by {data.latest.operator}
            {data.latest.elevated ? ' (elevated)' : ' (not elevated: some checks and most fixes need Administrator)'}.
            Report: <FileLink path={data.latest.file} />
            {data.latest.reboot_needed && data.latest.reboot_needed.length > 0 && <> · <strong>Reboot needed for {data.latest.reboot_needed.join(', ')}</strong></>}
          </p>

          <Card title="Fix issues" actions={<>
            <button className="btn ghost sm" onClick={() => setSel(Object.fromEntries(fixable.filter((c) => c.FixRisk === 'Low').map((c) => [c.Id, true])))}>Select low-risk fixes</button>
            <button className="btn ghost sm" onClick={() => setSel({})}>Clear</button>
          </>}>
            <div className="row gap wrap">
              <label className="check">
                <input type="checkbox" checked={elevated} onChange={(e) => setElevated(e.target.checked)} />
                Run fixes in an elevated window (Windows asks for Administrator approval)
              </label>
              <span className="spacer" />
              <button className="btn primary" disabled={!selected.length || busy || running}
                onClick={() => start('readiness-fix', { ids: selected, elevated })}>
                Fix {selected.length || ''} selected
              </button>
            </div>
            <p className="muted small">Medium-risk fixes (firewall, TLS, LSA protection, folder permissions) are never pre-selected. Read the remediation before you choose them. Domain GPOs can override local fixes.</p>
          </Card>

          {CATS.map((cat) => {
            const items = checks.filter((c) => c.Category === cat)
            if (!items.length) return null
            return (
              <Card key={cat} title={cat}>
                <table className="table">
                  <thead><tr><th /><th>ID</th><th>Status</th><th>Check</th><th>Found</th><th>Fix</th></tr></thead>
                  <tbody>
                    {items.map((c) => {
                      const canFix = c.AutoFix && (c.Status === 'Fail' || c.Status === 'Warn')
                      return (
                        <React.Fragment key={c.Id}>
                          <tr className={open[c.Id] ? 'open' : ''}>
                            <td>{canFix && <input type="checkbox" aria-label={'Select ' + c.Id} checked={!!sel[c.Id]} onChange={(e) => setSel({ ...sel, [c.Id]: e.target.checked })} />}</td>
                            <td className="mono">{c.Id}</td>
                            <td><Chip status={c.Status} /></td>
                            <td>{c.Name}</td>
                            <td className="muted small">{c.Detail}</td>
                            <td>
                              {c.Status !== 'Pass' && c.Remediation && (
                                <button className="btn ghost sm" onClick={() => setOpen({ ...open, [c.Id]: !open[c.Id] })}>
                                  {open[c.Id] ? 'Hide' : canFix ? `Auto-fix (${c.FixRisk})` : 'How to fix'}
                                </button>
                              )}
                            </td>
                          </tr>
                          {open[c.Id] && (
                            <tr className="detail"><td /><td colSpan={5}>
                              <div className="remediation">{c.Remediation}</div>
                              <div className="muted small">
                                {c.AutoFix ? `Automatic fix available · risk ${c.FixRisk}` : 'No automatic fix: do this manually or by GPO'}
                                {c.NeedsAdmin ? ' · needs Administrator' : ''}{c.NeedsReboot ? ' · reboot required' : ''}
                                {c.Reference ? ` · ${c.Reference}` : ''}
                              </div>
                            </td></tr>
                          )}
                        </React.Fragment>
                      )
                    })}
                  </tbody>
                </table>
              </Card>
            )
          })}
        </>
      ) : (
        data && data.powershell && <Callout title="No readiness report yet">Run the checks to see where this server stands.</Callout>
      )}

      <JobConsole jobId={jobId} onFinished={() => { load(); refresh(false) }} />
    </div>
  )
}

const Stat = ({ label, n, kind }) => (
  <div className={'stat ' + kind}><div className="stat-n">{n}</div><div className="muted small">{label}</div></div>
)
