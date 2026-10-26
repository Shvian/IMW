import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Card, Chip, Callout, Field, JobConsole, KeyValueEditor, JsonEditor, useAction, useLatestJob, useToast } from '../components.jsx'

const clone = (o) => JSON.parse(JSON.stringify(o))

export default function Connections({ ov, refresh }) {
  const [cfg, setCfg] = useState(null)
  const [saved, setSaved] = useState(null)
  const [warnings, setWarnings] = useState([])
  const [policy, setPolicy] = useState({ calls: 5000, seconds: 300 })
  const [preflight, setPreflight] = useState(null)
  const [showJson, setShowJson] = useState(false)
  const [jobId, setJobId] = useLatestJob(['preflight'], ov.job)
  const [run, busy] = useAction()
  const toast = useToast()

  const load = async () => {
    const r = await api('config')
    setCfg(clone(r.phase2)); setSaved(r.phase2); setWarnings(r.warnings); setPolicy(r.policy)
  }
  const loadPreflight = () => api('preflight').then((r) => setPreflight(r.results ? r : null)).catch(() => {})
  useEffect(() => { load(); loadPreflight() }, [])
  if (!cfg) return <p className="muted">Loading…</p>

  const dirty = JSON.stringify(cfg) !== JSON.stringify(saved)
  const set = (path, value) => {
    const next = clone(cfg)
    let o = next
    path.slice(0, -1).forEach((k) => { o[k] = o[k] || {}; o = o[k] })
    o[path[path.length - 1]] = value
    setCfg(next)
  }
  const save = () => run(async () => {
    const r = await api('config/phase2', { method: 'PUT', body: { config: cfg } })
    setWarnings(r.warnings); setSaved(clone(cfg)); refresh(false)
    return r
  }, (r) => `Saved (${r.changes} changes)`)

  const running = ov.job && ov.job.state === 'running'
  const grant = cfg.delinea.grant_type || 'password'

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Connections</h1>
          <p className="muted">Tenant addresses, service accounts and rate limits. Credentials are entered separately and held in memory only.</p>
        </div>
        <div className="row gap">
          {dirty && <Chip status="warn">Unsaved changes</Chip>}
          <button className="btn primary" disabled={!dirty || busy} onClick={save}>Save settings</button>
        </div>
      </div>

      {warnings.length > 0 && (
        <Callout kind="warn" title="Check these settings">
          <ul className="bullets">{warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
        </Callout>
      )}

      <div className="grid2">
        <Card title="CyberArk Privilege Cloud">
          <Field label="Identity token URL" hint="https://<tenant>.id.cyberark.cloud/oauth2/platformtoken">
            <input value={cfg.cyberark.token_url || ''} onChange={(e) => set(['cyberark', 'token_url'], e.target.value)} />
          </Field>
          <Field label="Privilege Cloud API base URL" hint="https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API">
            <input value={cfg.cyberark.api_base_url || ''} onChange={(e) => set(['cyberark', 'api_base_url'], e.target.value)} />
          </Field>
          <Field label="Service user (OAuth client ID)">
            <input value={cfg.cyberark.client_id || ''} onChange={(e) => set(['cyberark', 'client_id'], e.target.value)} />
          </Field>
          <RateLimits sec={cfg.cyberark} onChange={(k, v) => set(['cyberark', k], v)} policy={policy} />
          <Credential system="cyberark" label="Client secret" isSet={ov.session.credentials.cyberark} refresh={refresh} toast={toast} saveFirst={dirty} />
        </Card>

        <Card title="Delinea Secret Server">
          <Field label="Base URL" hint="https://<server>/SecretServer">
            <input value={cfg.delinea.base_url || ''} onChange={(e) => set(['delinea', 'base_url'], e.target.value)} />
          </Field>
          <Field label="Token URL (optional)" hint="Leave empty to use <base URL>/oauth2/token">
            <input value={cfg.delinea.token_url || ''} onChange={(e) => set(['delinea', 'token_url'], e.target.value)} />
          </Field>
          <Field label="Sign-in type">
            <select value={grant} onChange={(e) => set(['delinea', 'grant_type'], e.target.value)}>
              <option value="password">API user name and password</option>
              <option value="client_credentials">Client credentials (SDK client / platform)</option>
            </select>
          </Field>
          {grant === 'password' ? (
            <Field label="API user name"><input value={cfg.delinea.username || ''} onChange={(e) => set(['delinea', 'username'], e.target.value)} /></Field>
          ) : (
            <Field label="Client ID"><input value={cfg.delinea.client_id || ''} onChange={(e) => set(['delinea', 'client_id'], e.target.value)} /></Field>
          )}
          <RateLimits sec={cfg.delinea} onChange={(k, v) => set(['delinea', k], v)} policy={policy} />
          <Credential system="delinea" label={grant === 'password' ? 'Password' : 'Client secret'} isSet={ov.session.credentials.delinea}
            refresh={refresh} toast={toast} saveFirst={dirty}
            note="Before cutover you may have no access to Delinea. The rehearsal never contacts it." />
        </Card>
      </div>

      <div className="grid2">
        <Card title="Directory mapping (group members)">
          <p className="muted small">Maps the domain part of a Delinea group (CORP\Unix-Admins) to the CyberArk Identity directory searched for it. Use * for the default; Vault means CyberArk-internal.</p>
          <KeyValueEditor value={cfg.directory_map} onChange={(v) => set(['directory_map'], v)} keyLabel="Delinea domain" valueLabel="Identity directory" keyPlaceholder="CORP" valuePlaceholder="corp.example.com" />
          <label className="check"><input type="checkbox" checked={!!cfg.strip_domain_prefix} onChange={(e) => set(['strip_domain_prefix'], e.target.checked)} /> Remove the domain prefix from member names (CORP\Unix-Admins → Unix-Admins)</label>
        </Card>
        <Card title="New Safe defaults">
          <Field label="Managing CPM" hint="Leave empty for no CPM until rotation is planned">
            <input value={cfg.safe_defaults.managingCPM || ''} onChange={(e) => set(['safe_defaults', 'managingCPM'], e.target.value)} />
          </Field>
          <Field label="Days of version retention">
            <input type="number" min="0" value={cfg.safe_defaults.numberOfDaysRetention ?? 7} onChange={(e) => set(['safe_defaults', 'numberOfDaysRetention'], Number(e.target.value))} />
          </Field>
          <Field label="Description"><input value={cfg.safe_defaults.description || ''} onChange={(e) => set(['safe_defaults', 'description'], e.target.value)} /></Field>
          <label className="check"><input type="checkbox" checked={!!(cfg.account_defaults && cfg.account_defaults.automaticManagementEnabled)}
            onChange={(e) => set(['account_defaults', 'automaticManagementEnabled'], e.target.checked)} /> Enable automatic password management on migrated accounts</label>
        </Card>
      </div>

      <Card title="Tenant preflight (read-only)" actions={
        <button className="btn" disabled={busy || running || !ov.session.credentials.cyberark || dirty}
          onClick={() => run(async () => { const j = await api('jobs', { method: 'POST', body: { action: 'preflight' } }); setJobId(j.id) })}>
          Run preflight
        </button>}>
        <p className="muted small">Signs in, checks API rights, that the mapped platforms are active, that the directories and groups exist, and which Safe names are already taken. Changes nothing.</p>
        {preflight && preflight.results && (
          <table className="table compact">
            <thead><tr><th>Status</th><th>Check</th><th>Detail</th></tr></thead>
            <tbody>{preflight.results.map((r, i) => (
              <tr key={i}><td><Chip status={r.status} /></td><td>{r.check}</td><td className="muted small">{r.detail}</td></tr>
            ))}</tbody>
          </table>
        )}
        <JobConsole jobId={jobId} height={220} onFinished={() => { loadPreflight(); refresh(false) }} />
      </Card>

      <Card title="Advanced">
        <button className="btn ghost sm" onClick={() => setShowJson(!showJson)}>{showJson ? 'Hide' : 'Show'} the full settings file (JSON)</button>
        {showJson && <JsonEditor value={cfg} onApply={(v) => { setCfg(v); toast('Applied to the form. Save settings to keep it.') }} />}
      </Card>
    </div>
  )
}

function RateLimits({ sec, onChange, policy }) {
  const rpm = Number(sec.requests_per_minute || 0)
  const cap = Number(sec.max_calls_per_window || 0)
  const win = Number(sec.window_seconds || 300)
  const per5 = Math.min(rpm ? rpm * 5 : Infinity, cap ? (cap * policy.seconds) / win : Infinity)
  return (
    <div className="ratelimits">
      <div className="row gap">
        <Field label="Calls per minute"><input type="number" min="1" value={sec.requests_per_minute ?? ''} onChange={(e) => onChange('requests_per_minute', Number(e.target.value))} /></Field>
        <Field label="Hard cap per window"><input type="number" min="1" value={sec.max_calls_per_window ?? ''} onChange={(e) => onChange('max_calls_per_window', Number(e.target.value))} /></Field>
        <Field label="Window (seconds)"><input type="number" min="1" value={sec.window_seconds ?? ''} onChange={(e) => onChange('window_seconds', Number(e.target.value))} /></Field>
      </div>
      <div className={'small ' + (per5 >= policy.calls ? 'error-text' : 'muted')}>
        At most about {isFinite(per5) ? Math.round(per5) : 'unlimited'} calls per 5 minutes (starting policy: below {policy.calls}). The client slows down further on any 429.
      </div>
    </div>
  )
}

function Credential({ system, label, isSet, refresh, toast, note, saveFirst }) {
  const [value, setValue] = useState('')
  const [result, setResult] = useState(null)
  const [run, busy] = useAction()
  const setCred = () => run(async () => {
    await api('credentials', { method: 'POST', body: { system, value } })
    setValue(''); setResult(null); refresh(false)
  }, 'Credential held in memory for this session')
  const test = () => run(async () => {
    const r = await api('connections/test', { method: 'POST', body: { system } })
    setResult(r); refresh(false)
  })
  return (
    <div className="credential">
      <div className="row between">
        <strong>{label}</strong>
        <Chip status={isSet ? 'ok' : 'todo'}>{isSet ? 'Set for this session' : 'Not set'}</Chip>
      </div>
      <div className="row gap">
        <input type="password" autoComplete="new-password" value={value} placeholder={isSet ? 'Enter again to replace' : 'Paste or type'}
          onChange={(e) => setValue(e.target.value)} aria-label={label} onKeyDown={(e) => e.key === 'Enter' && value && setCred()} />
        <button className="btn" disabled={!value || busy} onClick={setCred}>Set</button>
        {isSet && <button className="btn ghost" disabled={busy} onClick={() => run(async () => { await api('credentials/' + system, { method: 'DELETE' }); refresh(false) }, 'Credential dropped')}>Clear</button>}
        <button className="btn ghost" disabled={!isSet || busy || saveFirst} title={saveFirst ? 'Save settings first' : ''} onClick={test}>Test sign-in</button>
      </div>
      <div className="muted small">Kept in the UI server's memory only. Never saved, logged or shown again. Dropped when the session ends.{note ? ' ' + note : ''}</div>
      {result && (
        <Callout kind={result.ok ? 'ok' : 'error'} title={result.ok ? 'Sign-in OK' : 'Sign-in failed'}>
          {result.message}{result.hint ? <div className="small">{result.hint}</div> : null}
        </Callout>
      )}
    </div>
  )
}
