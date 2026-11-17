// Runs the browser tests against the Workbench: a fresh workspace with the test's sample files in its
// inbox, the Workbench started on it, then the Playwright test. Needs Node.js and Playwright.
//
//   dotnet build dotnet/src/Imw
//   node dotnet/tests/ui/run.js [test ...] [--shots <folder>]
//
// With no test named, all three run. IMW_EXE runs another build (for example dist/IMW.exe) instead of
// the Debug build. Run it from the repository root.
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const S = (...p) => path.join(ROOT, 'samples', ...p);
// The sample files each test expects in its inbox.
const TESTS = {
  'ui_browser_test.js': ['delinea_export.csv', 'delinea_permissions.csv', 'delinea_permissions_extra.csv',
    'keepass_export.xml', 'accounts_by_group.xlsx'].map(f => S(f)),
  'ui_browser_reports_test.js': fs.readdirSync(S('delinea_reports')).filter(f => f.endsWith('.csv')).map(f => S('delinea_reports', f)),
  'ui_browser_personal_test.js': fs.readdirSync(S('personal_safes')).filter(f => f.endsWith('.csv')).map(f => S('personal_safes', f))
    .concat([S('delinea_reports', 'lauserslist.csv')]),
};

const args = process.argv.slice(2);
const si = args.indexOf('--shots');
const shots = si >= 0 ? path.resolve(args.splice(si, 2)[1]) : '';
const names = args.length ? args : Object.keys(TESTS);

function start(ws, logFile) {
  const exe = process.env.IMW_EXE;
  const dll = path.join(ROOT, 'dotnet', 'src', 'Imw', 'bin', 'Debug', 'net10.0', 'IMW.dll');
  const [cmd, pre] = exe ? [exe, []] : ['dotnet', [dll]];
  const log = fs.openSync(logFile, 'w');
  return spawn(cmd, [...pre, 'ui', '-w', ws, '--no-browser', '--insecure-plaintext-secrets'], {
    stdio: ['ignore', log, log], env: { ...process.env, IMW_UI_TEST_PASSWORD: process.env.IMW_UI_TEST_PASSWORD || 'test-pass', IMW_UI_NO_OPEN: '1' } });
}

async function runOne(name) {
  if (!TESTS[name]) throw new Error(`unknown test ${name}; known: ${Object.keys(TESTS).join(', ')}`);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'imw-ui-'));
  const ws = path.join(tmp, 'ws');
  fs.mkdirSync(path.join(ws, 'inbox'), { recursive: true });
  TESTS[name].forEach(f => fs.copyFileSync(f, path.join(ws, 'inbox', path.basename(f))));
  const logFile = path.join(tmp, 'ui.log');
  const proc = start(ws, logFile);
  try {
    for (let i = 0; i < 120 && !/\?t=\S+/.test(fs.readFileSync(logFile, 'utf8')); i++) await new Promise(r => setTimeout(r, 500));
    if (shots) fs.mkdirSync(shots, { recursive: true });
    const r = spawnSync('node', [path.join(__dirname, name), logFile].concat(shots ? [shots] : []), { encoding: 'utf8' });
    const ok = r.status === 0 && /PASS/.test(r.stdout);
    console.log(`== ${name} ${ok ? 'PASS' : 'FAIL'}`);
    if (!ok) console.log((r.stdout + r.stderr).split('\n').filter(l => !/^\s+at /.test(l)).join('\n'));
    return ok;
  } finally {
    proc.kill();
    await new Promise(r => setTimeout(r, 300));
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

(async () => {
  let failed = 0;
  for (const n of names) if (!(await runOne(n))) failed++;
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
