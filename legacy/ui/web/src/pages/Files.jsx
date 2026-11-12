import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Card, Chip, Callout, DropZone, FilesTable, useAction } from '../components.jsx'

export default function Files({ ov, refresh, go }) {
  const [files, setFiles] = useState({ files: [], inputs: {} })
  const [results, setResults] = useState({})
  const [busyKind, setBusyKind] = useState('')
  const [run] = useAction()

  const load = () => api('files').then(setFiles).catch(() => {})
  useEffect(() => { load() }, [])

  const upload = (kind) => (file) => {
    setBusyKind(kind)
    run(async () => {
      const r = await api('files/' + kind, { method: 'POST', file })
      setResults((x) => ({ ...x, [kind]: r }))
      load(); refresh(false)
      return r
    }, (r) => `Saved ${r.saved_as}`).finally(() => setBusyKind(''))
  }

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Data files</h1>
          <p className="muted">Drop the Delinea exports here. Secret values and attachments are removed in memory before anything is saved.</p>
        </div>
        {files.inputs.export && <button className="btn primary" onClick={() => go('mapping')}>Next: mapping rules</button>}
      </div>

      <Callout title="Which export to use">
        Use a metadata-only Secret Server report that includes Secret ID, Secret Name, Folder Path, template fields and Username. A full export with passwords works too. The passwords are stripped here, but the original file still holds them, so delete it securely afterwards.
      </Callout>

      <div className="grid2">
        <Card title="1. Secret export (required)" actions={files.inputs.export && <Chip status="ok">Uploaded</Chip>}>
          <DropZone label="Drop the Delinea secret export" busy={busyKind === 'export'} onFile={upload('export')} />
          <UploadResult r={results.export} />
          {files.inputs.export && <button className="btn ghost sm" onClick={() => run(async () => { await api('files/export', { method: 'DELETE' }); load(); refresh(false) }, 'Removed')}>Remove</button>}
        </Card>
        <Card title="2. Permissions export (recommended)" actions={files.inputs.permissions && <Chip status="ok">Uploaded</Chip>}>
          <DropZone label="Drop the folder and secret permissions CSV" busy={busyKind === 'permissions'} onFile={upload('permissions')}
            hint="Columns: Folder Path, Secret Name, Secret ID, Group, Permission" />
          <UploadResult r={results.permissions} />
          {files.inputs.permissions && <button className="btn ghost sm" onClick={() => run(async () => { await api('files/permissions', { method: 'DELETE' }); load(); refresh(false) }, 'Removed')}>Remove</button>}
        </Card>
      </div>

      <Card title="Bring back review files edited elsewhere (optional)">
        <p className="muted small">If you edited Migration_Review.csv or Safe_Members_Review.csv in Excel, drop them here. They replace the current review files, and the old ones are kept under history/. Run Plan again afterwards.</p>
        <div className="grid2">
          <DropZone label="Drop Migration_Review.csv" busy={busyKind === 'review'} onFile={upload('review')} />
          <DropZone label="Drop Safe_Members_Review.csv" busy={busyKind === 'members'} onFile={upload('members')} />
        </div>
        <UploadResult r={results.review} />
        <UploadResult r={results.members} />
      </Card>

      <Card title="Workspace files" actions={<button className="btn ghost sm" onClick={load}>Refresh</button>}>
        <p className="muted small">Click to download, or drag a file onto the desktop or a folder (Edge and Chrome). None of these files contain secret values.</p>
        <FilesTable files={files.files} />
      </Card>
    </div>
  )
}

function UploadResult({ r }) {
  if (!r) return null
  return (
    <div className="upload-result">
      <div className="small">
        <strong>{r.original_name}</strong> saved as <code>{r.saved_as}</code>
        {r.sections != null && <> · {r.sections} template sections</>} · {r.rows} rows · {r.encoding}
      </div>
      {r.dropped_columns.length > 0 && (
        <div className="small">Removed columns: {r.dropped_columns.map((c) => `${c.name} (${c.kind})`).join(', ')}</div>
      )}
      {r.warnings.map((w, i) => <Callout key={i} kind="warn">{w}</Callout>)}
      <div className="muted small mono">sha256 original {r.original_sha256.slice(0, 16)}… · saved {r.saved_sha256.slice(0, 16)}…</div>
    </div>
  )
}
