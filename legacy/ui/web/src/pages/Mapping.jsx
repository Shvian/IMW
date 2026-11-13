import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Card, Chip, Callout, Field, JobConsole, KeyValueEditor, JsonEditor, useAction, useLatestJob, useToast } from '../components.jsx'

const clone = (o) => JSON.parse(JSON.stringify(o))
const PERMS = ['', 'List', 'View', 'Edit', 'Owner']

export default function Mapping({ ov, refresh, go }) {
  const [cfg, setCfg] = useState(null)
  const [saved, setSaved] = useState(null)
  const [roles, setRoles] = useState(['Owner', 'Editor', 'User', 'Viewer'])
  const [showJson, setShowJson] = useState(false)
  const [jobId, setJobId] = useLatestJob(['phase1'], ov.job)
  const [run, busy] = useAction()
  const toast = useToast()

  const load = async () => {
    const r = await api('config')
    const m = r.mapping
    m.group_rules = (m.group_rules || []).filter((x) => x && typeof x === 'object')
    setCfg(clone(m)); setSaved(clone(m))
    setRoles(Object.keys(r.phase2.role_permissions || {}).length ? Object.keys(r.phase2.role_permissions) : roles)
  }
  useEffect(() => { load() }, [])
  if (!cfg) return <p className="muted">Loading…</p>

  const dirty = JSON.stringify(cfg) !== JSON.stringify(saved)
  const upd = (k, v) => setCfg({ ...cfg, [k]: v })
  const save = () => run(async () => {
    await api('config/mapping', { method: 'PUT', body: { config: cfg } })
    setSaved(clone(cfg))
  }, 'Mapping rules saved')

  const generate = () => run(async () => {
    const j = await api('jobs', { method: 'POST', body: { action: 'phase1' } })
    setJobId(j.id); refresh(false)
  })
  const running = ov.job && ov.job.state === 'running'
  const exportReady = ov.steps.find((s) => s.id === 'files').status === 'done'
  const mappingDone = ov.steps.find((s) => s.id === 'mapping').status !== 'todo'

  const rules = cfg.group_rules || []
  const setRule = (i, patch) => upd('group_rules', rules.map((r, j) => (j === i ? { ...r, ...patch } : r)))
  const folderRules = cfg.folder_rules || []
  const setFolder = (i, patch) => upd('folder_rules', folderRules.map((r, j) => (j === i ? { ...r, ...patch } : r)))

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Mapping rules</h1>
          <p className="muted">Decide which CyberArk Safe each secret goes to (RBAC flattening by access group), and which platform it uses. Then generate the mapping for review.</p>
        </div>
        <div className="row gap">
          {dirty && <Chip status="warn">Unsaved changes</Chip>}
          <button className="btn" disabled={!dirty || busy} onClick={save}>Save rules</button>
          <button className="btn primary" disabled={dirty || busy || running || !exportReady} title={!exportReady ? 'Upload the export first' : dirty ? 'Save the rules first' : ''} onClick={generate}>
            Generate mapping
          </button>
        </div>
      </div>

      {mappingDone && <Callout kind="warn" title="Generating again replaces the review files">Edits made under Review are overwritten. The current files are saved under history/ first.</Callout>}

      <Card title="Safe names">
        <div className="row gap wrap">
          <Field label="Prefix for every derived Safe" hint="Optional, e.g. DL-. Counts toward the 28-character limit.">
            <input value={(cfg.safe_name && cfg.safe_name.prefix) || ''} onChange={(e) => upd('safe_name', { ...cfg.safe_name, prefix: e.target.value })} />
          </Field>
          <Field label="When no rule matches" hint="How to name the Safe from the Delinea folder">
            <select value={cfg.fallback_strategy || 'folder_leaf'} onChange={(e) => upd('fallback_strategy', e.target.value)}>
              <option value="folder_leaf">Last folder name (\IT\Windows\Servers → Servers)</option>
              <option value="folder_path">Whole path (→ IT-Windows-Servers)</option>
              <option value="unmapped">UNMAPPED (force a decision in review)</option>
            </select>
          </Field>
        </div>
        <p className="muted small">Invalid characters (\ / : * ? " &lt; &gt; |) become "-". Names over 28 characters are shortened, and names that collide get a -2 suffix. All of these are flagged for review.</p>
      </Card>

      <Card title="Group rules (first match wins)" actions={
        <button className="btn ghost sm" onClick={() => upd('group_rules', [...rules, { group: '', safe: '' }])}>+ Add rule</button>}>
        <p className="muted small">Each secret goes to the Safe of the first rule whose group holds access to it. Use a pattern with {'{1}'} to build Safe names from part of the group name. Minimum permission ignores weaker grants (for example a helpdesk with List on everything).</p>
        <table className="table compact">
          <thead><tr><th>Match</th><th>Group or pattern</th><th>Target Safe</th><th>Minimum permission</th><th /></tr></thead>
          <tbody>
            {rules.map((r, i) => {
              const isPattern = r.group_pattern != null
              return (
                <tr key={i}>
                  <td>
                    <select value={isPattern ? 'pattern' : 'exact'} aria-label="Match type" onChange={(e) => {
                      const v = r.group ?? r.group_pattern ?? ''
                      const { group, group_pattern, ...rest } = r
                      upd('group_rules', rules.map((x, j) => (j === i ? (e.target.value === 'pattern' ? { ...rest, group_pattern: v } : { ...rest, group: v }) : x)))
                    }}>
                      <option value="exact">Exact group</option>
                      <option value="pattern">Regex pattern</option>
                    </select>
                  </td>
                  <td><input className="mono" value={isPattern ? r.group_pattern : r.group || ''} placeholder={isPattern ? '^CORP\\\\APP-(.+)-Owners$' : 'CORP\\Unix-Admins'}
                    aria-label="Group" onChange={(e) => setRule(i, isPattern ? { group_pattern: e.target.value } : { group: e.target.value })} /></td>
                  <td><input value={r.safe || ''} placeholder="UNIX-Admins" aria-label="Safe" onChange={(e) => setRule(i, { safe: e.target.value })} /></td>
                  <td>
                    <select value={r.min_permission || ''} aria-label="Minimum permission" onChange={(e) => {
                      const { min_permission, ...rest } = r
                      upd('group_rules', rules.map((x, j) => (j === i ? (e.target.value ? { ...rest, min_permission: e.target.value } : rest) : x)))
                    }}>{PERMS.map((p) => <option key={p} value={p}>{p || 'Any'}</option>)}</select>
                  </td>
                  <td className="row">
                    <button className="btn ghost sm" disabled={i === 0} aria-label="Move up" onClick={() => { const x = [...rules]; [x[i - 1], x[i]] = [x[i], x[i - 1]]; upd('group_rules', x) }}>↑</button>
                    <button className="btn ghost sm" aria-label="Remove rule" onClick={() => upd('group_rules', rules.filter((_, j) => j !== i))}>✕</button>
                  </td>
                </tr>
              )
            })}
            {!rules.length && <tr><td colSpan={5} className="muted">No group rules. Every secret uses the folder rules or the fallback.</td></tr>}
          </tbody>
        </table>
      </Card>

      <Card title="Folder rules (used when no group rule matches)" actions={
        <button className="btn ghost sm" onClick={() => upd('folder_rules', [...folderRules, { folder_prefix: '', safe: '' }])}>+ Add rule</button>}>
        <table className="table compact">
          <thead><tr><th>Folder (and its subfolders)</th><th>Target Safe</th><th /></tr></thead>
          <tbody>
            {folderRules.map((r, i) => (
              <tr key={i}>
                <td><input value={r.folder_prefix} placeholder="\Infrastructure\Network" aria-label="Folder" onChange={(e) => setFolder(i, { folder_prefix: e.target.value })} /></td>
                <td><input value={r.safe} placeholder="NET-Devices" aria-label="Safe" onChange={(e) => setFolder(i, { safe: e.target.value })} /></td>
                <td><button className="btn ghost sm" aria-label="Remove rule" onClick={() => upd('folder_rules', folderRules.filter((_, j) => j !== i))}>✕</button></td>
              </tr>
            ))}
            {!folderRules.length && <tr><td colSpan={3} className="muted">None</td></tr>}
          </tbody>
        </table>
      </Card>

      <div className="grid2">
        <Card title="Template → CyberArk platform">
          <KeyValueEditor value={cfg.platform_map} onChange={(v) => upd('platform_map', v)} keyLabel="Delinea template" valueLabel="Platform ID" keyPlaceholder="Windows Account" valuePlaceholder="WinServerLocal" />
          <Field label="Platform when the template is not listed">
            <input value={cfg.default_platform || ''} onChange={(e) => upd('default_platform', e.target.value)} />
          </Field>
        </Card>
        <Card title="Delinea permission → Safe member role">
          <KeyValueEditor value={cfg.permission_map} onChange={(v) => upd('permission_map', v)} keyLabel="Delinea permission" valueLabel="CyberArk role" options={roles} />
          <h3>Secret field per template</h3>
          <p className="muted small">The Delinea field slug that holds the secret. Find it under Admin → Secret Templates → Fields.</p>
          <KeyValueEditor value={cfg.secret_field_slugs} onChange={(v) => upd('secret_field_slugs', v)} keyLabel="Template" valueLabel="Field slug" valuePlaceholder="private-key" />
          <Field label="Default field slug"><input value={cfg.default_secret_field || ''} onChange={(e) => upd('default_secret_field', e.target.value)} /></Field>
        </Card>
      </div>

      <Card title="Advanced">
        <button className="btn ghost sm" onClick={() => setShowJson(!showJson)}>{showJson ? 'Hide' : 'Show'} the full rules file (JSON)</button>
        {showJson && <JsonEditor value={cfg} onApply={(v) => { setCfg(v); toast('Applied to the form. Save rules to keep it.') }} />}
      </Card>

      <JobConsole jobId={jobId} onFinished={(j) => { refresh(false); if (j.exit_code === 0) toast('Mapping generated. Continue to Review.', 'ok') }} />
      {mappingDone && <div className="row end"><button className="btn primary" onClick={() => go('review')}>Next: review</button></div>}
    </div>
  )
}
