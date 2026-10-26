// Browser test of the migration UI: drives the real pages in Chromium against the
// Phase 2 mock APIs. Needs Node with Playwright and a Chromium build.
//
//   node ui/tests/ui_browser_test.js [screenshot-dir]
//
// Walks the guided flow (operator, connections, credentials, sign-in test, drag-in
// uploads, mapping rules, Phase 1, review edit, plan, rehearsal with typed
// confirmation, results and audit verification) and fails on any browser console
// error, including Content-Security-Policy violations.

const { chromium } = require('playwright')
const { spawn, spawnSync } = require('child_process')
const fs = require('fs')
const os = require('os')
const path = require('path')

const ROOT = path.resolve(__dirname, '..', '..')
const PY = process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3')
const SHOTS = process.argv[2] || fs.mkdtempSync(path.join(os.tmpdir(), 'ui_shots_'))
const failures = []
const check = (cond, msg) => { console.log((cond ? '  PASS ' : '  FAIL ') + msg); if (!cond) failures.push(msg) }

function waitForLine(proc, re, ms = 20000) {
  return new Promise((resolve, reject) => {
    let buf = ''
    const t = setTimeout(() => reject(new Error('timeout waiting for ' + re)), ms)
    proc.stdout.on('data', (d) => {
      buf += d.toString()
      const m = buf.match(re)
      if (m) { clearTimeout(t); resolve(m) }
    })
  })
}

async function main() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'ui_browser_'))
  const syn = path.join(work, 'synthetic')
  spawnSync(PY, [path.join(ROOT, 'tools', 'generate_synthetic_delinea.py'), '--secrets', '60', '--out', syn, '--with-values'])
  const mock = spawn(PY, [path.join(ROOT, 'phase2', 'tests', 'mock_apis.py'), '8765'], { stdio: 'ignore' })
  const ui = spawn(PY, ['-u', path.join(ROOT, 'ui', 'server', 'migration_ui.py'), '--workspace', path.join(work, 'ws'), '--no-browser'],
    { stdio: ['ignore', 'pipe', 'inherit'] })
  const [link] = await waitForLine(ui, /http:\/\/127\.0\.0\.1:\d+\/launch\?token=[\w-]+/)
  const browser = await chromium.launch()
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } })
  const errors = []
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()) })
  page.on('pageerror', (e) => errors.push(String(e)))
  const shot = (name) => page.screenshot({ path: path.join(SHOTS, name + '.png'), fullPage: true })
  const nav = (title) => page.locator('nav').getByRole('button', { name: title }).click()

  try {
    console.log('1. open from the one-time link')
    await page.goto(link)
    await page.getByText('Delinea → CyberArk migration').waitFor()
    check(page.url().endsWith('/'), 'token removed from the address bar after launch')
    await shot('01_overview')

    console.log('2. operator and connections')
    await page.getByLabel('Operator name').fill('Ian Tester')
    await page.getByLabel('Operator name').press('Enter')
    await page.getByText('Name recorded for the audit log').waitFor()
    await nav('Connections')
    const mockCfg = JSON.parse(fs.readFileSync(path.join(ROOT, 'phase2', 'tests', 'phase2_config_mock.json'), 'utf8'))
    await page.getByLabel('Identity token URL').fill(mockCfg.cyberark.token_url)
    await page.getByLabel('Privilege Cloud API base URL').fill(mockCfg.cyberark.api_base_url)
    await page.getByLabel('Service user (OAuth client ID)').fill(mockCfg.cyberark.client_id)
    await page.getByLabel(/^Base URL/).fill(mockCfg.delinea.base_url)
    await page.getByRole('textbox', { name: 'API user name' }).fill(mockCfg.delinea.username)
    await page.getByRole('button', { name: 'Save settings' }).click()
    await page.getByText(/Saved \(\d+ changes\)/).waitFor()
    await page.getByLabel('Client secret', { exact: true }).fill('test-secret')
    await page.getByLabel('Client secret', { exact: true }).press('Enter')
    await page.getByText('Credential held in memory for this session').first().waitFor()
    await page.getByLabel('Password', { exact: true }).fill('delinea-test')
    await page.getByLabel('Password', { exact: true }).press('Enter')
    await page.getByRole('button', { name: 'Test sign-in' }).first().click()
    await page.getByText('Sign-in OK').first().waitFor({ timeout: 30000 })
    check(true, 'settings saved, credentials set, CyberArk sign-in OK')
    const html = await page.content()
    check(!html.includes('test-secret') && !html.includes('delinea-test'), 'credentials are not in the page after entry')
    await shot('02_connections')

    console.log('3. drag files in')
    await nav('Data files')
    const inputs = page.locator('input[type=file]')
    await inputs.nth(0).setInputFiles(path.join(syn, 'delinea_export_synthetic.csv'))
    await page.getByText(/Removed columns: .*Password/).waitFor()
    await inputs.nth(1).setInputFiles(path.join(syn, 'delinea_permissions_synthetic.csv'))
    await page.getByText('Saved inputs/delinea_permissions.csv').waitFor()
    check(await page.getByText(/plaintext secret values/).count() > 0, 'upload result warns about plaintext in the original')
    await shot('03_files')

    console.log('4. mapping rules and Phase 1')
    await nav('Mapping rules')
    await page.getByRole('button', { name: /Show the full rules file/ }).click()
    const current = JSON.parse(await page.getByLabel('JSON').inputValue())
    const synRules = JSON.parse(fs.readFileSync(path.join(syn, 'mapping_config_synthetic.json'), 'utf8'))
    await page.getByLabel('JSON').fill(JSON.stringify({ ...current, group_rules: synRules.group_rules, fallback_strategy: 'folder_path' }, null, 2))
    await page.getByRole('button', { name: 'Apply JSON to the form' }).click()
    await page.getByRole('button', { name: 'Save rules' }).click()
    await page.getByText('Mapping rules saved').waitFor()
    await page.getByRole('button', { name: 'Generate mapping' }).click()
    await page.locator('.console').getByText('Finished', { exact: false }).first().waitFor({ timeout: 60000 })
    check(await page.locator('.console pre').innerText().then((t) => t.includes('Secrets processed')), 'Phase 1 output streamed into the page')
    await shot('04_mapping')

    console.log('5. review and plan')
    await nav('Review')
    await page.locator('table.grid tbody tr').first().waitFor()
    const rows = await page.locator('table.grid tbody tr').count()
    check(rows === 60, `review grid shows the accounts (${rows})`)
    await page.getByLabel('Migrate row 1', { exact: true }).click()
    await page.getByRole('button', { name: 'Save 1 change' }).click()
    await page.getByText('Saved 1 change', { exact: true }).waitFor()
    await shot('05_review_accounts')
    await page.getByRole('tab', { name: 'Safes' }).click()
    await page.getByText(/target Safes/).waitFor()
    await shot('06_review_safes')
    await page.getByRole('tab', { name: 'Plan' }).click()
    await page.getByRole('button', { name: 'Run plan' }).click()
    await page.getByText('Plan is clean for the current review files').waitFor({ timeout: 60000 })
    check(true, 'plan ran clean from the Review page')
    await shot('07_plan')

    console.log('6. rehearsal with typed confirmation')
    await nav('Rehearsal')
    await page.getByLabel('Safe prefix').fill('ZZ-')
    await page.getByRole('button', { name: 'Start rehearsal' }).click()
    const confirmBtn = page.getByRole('dialog').getByRole('button', { name: 'Start' })
    check(await confirmBtn.isDisabled(), 'Start stays disabled until the word is typed')
    await page.getByLabel('Type REHEARSE').fill('REHEARSE')
    await confirmBtn.click()
    await page.locator('.console-head').getByText(/Finished/).first().waitFor({ timeout: 120000 })
    await page.waitForTimeout(2000)
    const prog = await page.locator('.progress-grid').innerText()
    check(/Accounts\s+\d+ of 59 done, 2 failed/.test(prog), 'progress bars show the rehearsal result (2 unmapped-template rows fail the pre-check)')
    await shot('08_rehearsal')

    console.log('7. results and audit')
    await nav('Results')
    await page.getByRole('radio', { name: 'Rehearsal' }).click()
    await page.getByRole('tab', { name: 'Audit log' }).click()
    await page.getByRole('button', { name: 'Verify hash chain' }).click()
    await page.getByText('Audit log intact').waitFor()
    check(true, 'audit chain verified from the Results page')
    await shot('09_results_audit')
    await page.getByRole('tab', { name: 'Objects' }).click()
    await page.locator('table tbody tr').first().waitFor()
    await shot('10_results_objects')
    await nav('Server readiness')
    await page.getByText(/PowerShell is not available here|No readiness report yet/).waitFor()
    await shot('11_readiness')
    await nav('Migration')
    await page.getByText('Go / no-go').waitFor()
    await shot('12_migration')

    const errorsBeforeEnd = errors.slice()
    console.log('8. end session')
    await page.getByRole('button', { name: 'End session' }).click()
    await page.getByRole('heading', { name: 'Session ended' }).waitFor()
    const r = await page.evaluate(() => fetch('/api/overview').then((x) => x.status))
    check(r === 401, 'the session is gone on the server too')

    // After End session, the expected 401s are logged by the browser, so only errors before it count.
    check(errorsBeforeEnd.length === 0, 'no browser console errors or CSP violations' + (errorsBeforeEnd.length ? ': ' + errorsBeforeEnd.slice(0, 3).join(' | ') : ''))
  } catch (e) {
    failures.push(String(e))
    console.log('  FAIL ' + e)
    await shot('zz_failure').catch(() => {})
    if (errors.length) console.log('  console errors: ' + errors.join(' | '))
  } finally {
    await browser.close()
    ui.kill()
    mock.kill()
  }
  console.log(`\nScreenshots: ${SHOTS}`)
  console.log(failures.length ? `${failures.length} FAILED` : 'All browser checks passed.')
  process.exit(failures.length ? 1 : 0)
}

main()
