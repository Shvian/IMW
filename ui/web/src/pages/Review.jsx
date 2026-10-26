import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api.js'
import { Card, Chip, Callout, ConfirmDialog, FileLink, JobConsole, Pager, useAction, useLatestJob, useToast } from '../components.jsx'

const CORE = ['Migrate', 'Review_Status', 'Target CyberArk Safe', 'Target Platform ID', 'Account Name', 'Address', 'Username',
  'Secret Type', 'Delinea Secret ID', 'Delinea Secret Field', 'Delinea_Template', 'Delinea_Access_Groups', 'Review_Notes']
const LIMIT = 100

export default function Review({ ov, refresh, go }) {
  const [tab, setTab] = useState('accounts')
  const mapped = ov.steps.find((s) => s.id === 'mapping').status !== 'todo'
  if (!mapped) {
    return (
      <div className="stack">
        <h1>Review</h1>
        <Callout title="Nothing to review yet">Generate the mapping first. <button className="btn ghost sm" onClick={() => go('mapping')}>Go to mapping rules</button></Callout>
      </div>
    )
  }
  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Review</h1>
          <p className="muted">Check every target before anything is sent. Edits are validated, saved to the review files and audited, and the previous version is kept under history/.</p>
        </div>
        <div className="row gap small">
          <FileLink path="phase1_output/Migration_Review.csv" label="Migration_Review.csv" />
          <FileLink path="phase1_output/Safe_Members_Review.csv" label="Safe_Members_Review.csv" />
        </div>
      </div>
      <div className="tabs" role="tablist">
        {[['accounts', 'Accounts'], ['safes', 'Safes'], ['members', 'Safe members'], ['plan', 'Plan']].map(([id, label]) => (
          <button key={id} role="tab" aria-selected={tab === id} className={'tab' + (tab === id ? ' active' : '')} onClick={() => setTab(id)}>{label}</button>
        ))}
      </div>
      {tab === 'accounts' && <Accounts />}
      {tab === 'safes' && <Safes onShowAccounts={() => setTab('accounts')} />}
      {tab === 'members' && <Members />}
      {tab === 'plan' && <Plan ov={ov} refresh={refresh} go={go} />}
    </div>
  )
}

// ---------------------------------------------------------------- accounts grid
function Accounts() {
  const [q, setQ] = useState('')
  const [filter, setFilter] = useState('')
  const [offset, setOffset] = useState(0)
  const [data, setData] = useState(null)
  const [pending, setPending] = useState({})       // "row|column" -> value
  const [allCols, setAllCols] = useState(false)
  const [bulk, setBulk] = useState({ column: 'Migrate', value: 'N' })
  const [confirmBulk, setConfirmBulk] = useState(false)
  const [run, busy] = useAction()

  const load = useCallback(() => api(`review/accounts?q=${encodeURIComponent(q)}&filter=${encodeURIComponent(filter)}&offset=${offset}&limit=${LIMIT}`)
    .then(setData).catch(() => {}), [q, filter, offset])
  useEffect(() => { const t = setTimeout(load, 200); return () => clearTimeout(t) }, [load])

  if (!data) return <p className="muted">Loading…</p>
  const cols = allCols ? data.columns : CORE.filter((c) => data.columns.includes(c))
  const idx = Object.fromEntries(data.columns.map((c, i) => [c, i]))
  const n = Object.keys(pending).length
  const save = () => run(async () => {
    const changes = Object.entries(pending).map(([k, value]) => { const [row, column] = k.split('|'); return { row: Number(row), column, value } })
    const r = await api('review/accounts', { method: 'PUT', body: { changes } })
    setPending({}); load()
    return r
  }, (r) => `Saved ${r.changed} change${r.changed === 1 ? '' : 's'}`)

  return (
    <Card>
      <div className="toolbar">
        <input className="search" placeholder="Search any column" value={q} onChange={(e) => { setQ(e.target.value); setOffset(0) }} aria-label="Search" />
        <select value={filter} onChange={(e) => { setFilter(e.target.value); setOffset(0) }} aria-label="Filter">
          <option value="">All rows</option>
          <option value="review">Flagged for review</option>
          <option value="invalid">Safe name changed or invalid</option>
          <option value="included">Will migrate (Y)</option>
          <option value="excluded">Excluded (N)</option>
        </select>
        <label className="check small"><input type="checkbox" checked={allCols} onChange={(e) => setAllCols(e.target.checked)} /> All Delinea columns</label>
        <span className="spacer" />
        <span className="muted small">{data.matched} of {data.total} rows</span>
      </div>

      <div className="bulkbar">
        <span className="small">For all {data.matched} matching rows, set</span>
        <select value={bulk.column} onChange={(e) => setBulk({ column: e.target.value, value: e.target.value === 'Migrate' ? 'N' : '' })} aria-label="Bulk column">
          <option>Migrate</option><option>Target CyberArk Safe</option><option>Target Platform ID</option>
        </select>
        {bulk.column === 'Migrate' ? (
          <select value={bulk.value} onChange={(e) => setBulk({ ...bulk, value: e.target.value })} aria-label="Bulk value"><option>Y</option><option>N</option></select>
        ) : (
          <input value={bulk.value} onChange={(e) => setBulk({ ...bulk, value: e.target.value })} placeholder="new value" aria-label="Bulk value" />
        )}
        <button className="btn sm" disabled={!data.matched || busy || n > 0} title={n ? 'Save or discard your edits first' : ''} onClick={() => setConfirmBulk(true)}>Apply</button>
      </div>

      <div className="grid-scroll">
        <table className="table grid">
          <thead><tr>{cols.map((c) => <th key={c} className={data.editable.includes(c) ? 'editable' : ''}>{c}</th>)}</tr></thead>
          <tbody>
            {data.rows.map(({ row, values }) => (
              <tr key={row} className={values[idx.Review_Status] === 'REVIEW' ? 'flag' : ''}>
                {cols.map((c) => {
                  const key = row + '|' + c
                  const orig = values[idx[c]]
                  const v = key in pending ? pending[key] : orig
                  const edited = key in pending
                  if (!data.editable.includes(c)) {
                    if (c === 'Review_Status') return <td key={c}><Chip status={orig === 'REVIEW' ? 'warn' : 'ok'}>{orig}</Chip></td>
                    return <td key={c} className={c === 'Review_Notes' ? 'small muted wrapcell' : ''} title={orig}>{orig}</td>
                  }
                  const change = (nv) => setPending((p) => { const x = { ...p }; if (nv === orig) delete x[key]; else x[key] = nv; return x })
                  if (c === 'Migrate') {
                    return <td key={c} className={edited ? 'edited' : ''}>
                      <button className={'toggle ' + (v === 'N' ? 'off' : 'on')} onClick={() => change(v === 'N' ? 'Y' : 'N')} aria-label={`Migrate row ${row + 1}`}>{v || 'Y'}</button>
                    </td>
                  }
                  if (c === 'Secret Type') {
                    return <td key={c} className={edited ? 'edited' : ''}>
                      <select value={v} onChange={(e) => change(e.target.value)} aria-label={c}><option>password</option><option>key</option></select>
                    </td>
                  }
                  const badSafe = c === 'Target CyberArk Safe' && (v.length > 28 || /[\\/:*?"<>|]/.test(v))
                  return <td key={c} className={(edited ? 'edited ' : '') + (badSafe ? 'invalid' : '')}>
                    <input className="cell" value={v} onChange={(e) => change(e.target.value)} aria-label={c} title={badSafe ? 'Over 28 characters or has an invalid character' : ''} />
                  </td>
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="row between">
        <Pager offset={offset} limit={LIMIT} total={data.matched} onChange={setOffset} />
        <div className="row gap">
          {n > 0 && <button className="btn ghost" onClick={() => setPending({})}>Discard</button>}
          <button className="btn primary" disabled={!n || busy} onClick={save}>Save {n || ''} change{n === 1 ? '' : 's'}</button>
        </div>
      </div>

      <ConfirmDialog open={confirmBulk} title="Bulk edit" confirmLabel={`Update ${data.matched} rows`} onCancel={() => setConfirmBulk(false)}
        onConfirm={() => { setConfirmBulk(false); run(async () => { const r = await api('review/accounts', { method: 'PUT', body: { bulk: { ...bulk, q, filter } } }); load(); return r }, (r) => `Updated ${r.changed} rows`) }}>
        <p>Set <strong>{bulk.column}</strong> to <code>{bulk.value || '(empty)'}</code> on all {data.matched} rows matching the current search and filter (not only this page).</p>
        {bulk.column === 'Target CyberArk Safe' && <p className="muted small">To rename a whole Safe, use the Safes tab instead. It also updates the Safe members.</p>}
      </ConfirmDialog>
    </Card>
  )
}

// ---------------------------------------------------------------- safes
function Safes() {
  const [data, setData] = useState(null)
  const [renaming, setRenaming] = useState({})
  const [run, busy] = useAction()
  const load = () => api('review/safes').then(setData).catch(() => {})
  useEffect(() => { load() }, [])
  if (!data) return <p className="muted">Loading…</p>
  const issues = data.safes.filter((s) => s.problems.length || !s.members).length
  return (
    <Card>
      <p className="muted small">{data.safes.length} target Safes{issues ? `, ${issues} need attention` : ''}. Renaming a Safe here updates its accounts and its members together.</p>
      <table className="table">
        <thead><tr><th>Safe</th><th>Length</th><th>Accounts</th><th>Will migrate</th><th>Members</th><th>Problems</th><th>Rename</th></tr></thead>
        <tbody>
          {data.safes.map((s) => {
            const nv = renaming[s.safe]
            return (
              <tr key={s.safe} className={s.problems.length ? 'flag' : ''}>
                <td className="mono">{s.safe}</td>
                <td className={s.safe.length > data.max_length ? 'error-text' : ''}>{s.safe.length}</td>
                <td>{s.accounts}</td>
                <td>{s.included}</td>
                <td>{s.members ? s.members : <Chip status="warn">none</Chip>}</td>
                <td className="small">{s.problems.join('; ')}{!s.members && <span className="muted"> No members: only the migration service user will see it.</span>}</td>
                <td>
                  <div className="row gap">
                    <input className="cell" value={nv ?? s.safe} maxLength={data.max_length} onChange={(e) => setRenaming({ ...renaming, [s.safe]: e.target.value })} aria-label={'New name for ' + s.safe} />
                    <button className="btn sm" disabled={!nv || nv === s.safe || busy}
                      onClick={() => run(async () => { const r = await api('review/rename-safe', { method: 'POST', body: { old: s.safe, new: nv } }); setRenaming({}); load(); return r }, 'Safe renamed in accounts and members')}>
                      Rename
                    </button>
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </Card>
  )
}

// ---------------------------------------------------------------- members
function Members() {
  const [data, setData] = useState(null)
  const [safes, setSafes] = useState([])
  const [q, setQ] = useState('')
  const [offset, setOffset] = useState(0)
  const [pending, setPending] = useState({})
  const [del, setDel] = useState({})
  const [add, setAdd] = useState({ safe: '', member: '', role: '' })
  const [run, busy] = useAction()
  const load = useCallback(() => api(`review/members?q=${encodeURIComponent(q)}&offset=${offset}&limit=${LIMIT}`).then(setData).catch(() => {}), [q, offset])
  useEffect(() => { const t = setTimeout(load, 200); return () => clearTimeout(t) }, [load])
  useEffect(() => { api('review/safes').then((r) => setSafes(r.safes.map((s) => s.safe))).catch(() => {}) }, [])
  if (!data) return <p className="muted">No members file. Upload a permissions export and generate the mapping again.</p>
  const idx = Object.fromEntries(data.columns.map((c, i) => [c, i]))
  const show = ['Target CyberArk Safe', 'Member_Name', 'Member_Type', 'Delinea_Permission', 'CyberArk_Role', 'Secrets_With_Access', 'Review_Notes'].filter((c) => c in idx)
  const n = Object.keys(pending).length + Object.values(del).filter(Boolean).length
  const save = () => run(async () => {
    const changes = Object.entries(pending).map(([k, value]) => { const [row, column] = k.split('|'); return { row: Number(row), column, value } })
    const r = await api('review/members', { method: 'PUT', body: { changes, delete_rows: Object.keys(del).filter((k) => del[k]).map(Number) } })
    setPending({}); setDel({}); load()
    return r
  }, (r) => `Saved ${r.changed} change${r.changed === 1 ? '' : 's'}`)
  const role = add.role || data.roles[data.roles.length - 1]
  return (
    <Card>
      <div className="toolbar">
        <input className="search" placeholder="Search" value={q} onChange={(e) => { setQ(e.target.value); setOffset(0) }} aria-label="Search members" />
        <span className="spacer" />
        <span className="muted small">{data.matched} of {data.total} members</span>
      </div>
      <table className="table grid">
        <thead><tr><th>Remove</th>{show.map((c) => <th key={c} className={data.editable.includes(c) ? 'editable' : ''}>{c}</th>)}</tr></thead>
        <tbody>
          {data.rows.map(({ row, values }) => (
            <tr key={row} className={del[row] ? 'deleted' : values[idx.Review_Notes] ? 'flag' : ''}>
              <td><input type="checkbox" checked={!!del[row]} onChange={(e) => setDel({ ...del, [row]: e.target.checked })} aria-label={'Remove row ' + (row + 1)} /></td>
              {show.map((c) => {
                const key = row + '|' + c
                const orig = values[idx[c]]
                const v = key in pending ? pending[key] : orig
                const change = (nv) => setPending((p) => { const x = { ...p }; if (nv === orig) delete x[key]; else x[key] = nv; return x })
                if (c === 'CyberArk_Role') return <td key={c} className={key in pending ? 'edited' : ''}><select value={v} onChange={(e) => change(e.target.value)} aria-label="Role">{[...new Set([v, ...data.roles])].map((r) => <option key={r}>{r}</option>)}</select></td>
                if (c === 'Member_Name') return <td key={c} className={key in pending ? 'edited' : ''}><input className="cell" value={v} onChange={(e) => change(e.target.value)} aria-label="Member" /></td>
                return <td key={c} className={c === 'Review_Notes' ? 'small muted wrapcell' : ''}>{orig}</td>
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <div className="row between">
        <Pager offset={offset} limit={LIMIT} total={data.matched} onChange={setOffset} />
        <div className="row gap">
          {n > 0 && <button className="btn ghost" onClick={() => { setPending({}); setDel({}) }}>Discard</button>}
          <button className="btn primary" disabled={!n || busy} onClick={save}>Save {n || ''} change{n === 1 ? '' : 's'}</button>
        </div>
      </div>
      <h3>Add a member</h3>
      <div className="row gap wrap">
        <select value={add.safe} onChange={(e) => setAdd({ ...add, safe: e.target.value })} aria-label="Safe for new member">
          <option value="">Choose a Safe</option>{safes.map((s) => <option key={s}>{s}</option>)}
        </select>
        <input placeholder="CORP\Group-Name" value={add.member} onChange={(e) => setAdd({ ...add, member: e.target.value })} aria-label="New member name" />
        <select value={role} onChange={(e) => setAdd({ ...add, role: e.target.value })} aria-label="New member role">{data.roles.map((r) => <option key={r}>{r}</option>)}</select>
        <button className="btn" disabled={!add.safe || !add.member || busy}
          onClick={() => run(async () => { const r = await api('review/members', { method: 'PUT', body: { add_rows: [{ ...add, role }] } }); setAdd({ safe: '', member: '', role: '' }); load(); return r }, 'Member added')}>
          Add
        </button>
      </div>
    </Card>
  )
}

// ---------------------------------------------------------------- plan
function Plan({ ov, refresh, go }) {
  const [jobId, setJobId] = useLatestJob(['plan'], ov.job)
  const [run, busy] = useAction()
  const toast = useToast()
  const plan = ov.plan || {}
  const current = plan.review && plan.review === ov.review_shas.review && plan.members === ov.review_shas.members
  const running = ov.job && ov.job.state === 'running'
  return (
    <Card title="Plan (makes no changes)" actions={
      <button className="btn primary" disabled={busy || running} onClick={() => run(async () => { const j = await api('jobs', { method: 'POST', body: { action: 'plan' } }); setJobId(j.id) })}>
        Run plan
      </button>}>
      <p className="muted small">Validates the review files and shows what a migration would create, skip or retry, against the production ledger. A clean plan on the current files is required before the migration can start.</p>
      {plan.review ? (
        current
          ? <Callout kind={plan.exit_code === 0 ? 'ok' : 'error'} title={plan.exit_code === 0 ? 'Plan is clean for the current review files' : 'The plan found blockers'}>
              {plan.exit_code === 0 ? <>Next: a rehearsal in test Safes, or the migration. <button className="btn ghost sm" onClick={() => go('rehearsal')}>Go to rehearsal</button></> : 'Fix the BLOCKER lines below, save, and run the plan again.'}
            </Callout>
          : <Callout kind="warn" title="The review files changed since the last plan">Run the plan again.</Callout>
      ) : null}
      <JobConsole jobId={jobId} onFinished={(j) => { refresh(false); if (j.exit_code !== 0) toast('Plan found problems; see the output', 'error') }} />
    </Card>
  )
}
