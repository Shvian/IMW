// End-to-end browser test of the pam2pc UI (needs Node.js + Playwright).
//
//   PAM2PC_UI_TEST_PASSWORD=test-pass PAM2PC_UI_NO_OPEN=1 \
//     python -m pam2pc ui -w <ws> --no-browser --insecure-plaintext-secrets > ui.log &
//   (copy samples/delinea_export.csv, delinea_permissions.csv, keepass_export.xml,
//    accounts_by_group.xlsx into <ws>/inbox first)
//   node tests/ui_browser_test.js ui.log [screenshot-folder]
const { chromium } = require('playwright');
const fs = require('fs');

const PASSWORD = process.env.PAM2PC_UI_TEST_PASSWORD || 'test-pass';

(async () => {
  const log = fs.readFileSync(process.argv[2], 'utf8');
  const url = log.match(/https:\/\/127\.0\.0\.1:\d+\/\?t=\S+/)[0];
  const shots = process.argv[3];
  const shot = async (page, name) => { if (shots) await page.screenshot({ path: `${shots}/${name}.png` }); };
  const browser = await chromium.launch();
  // The certificate is self-signed for this computer; a real browser warns once (or not after --trust-cert).
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, ignoreHTTPSErrors: true });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => {
    if (m.type() === 'error' && !/status of (400|401|423)/.test(m.text())) errors.push(m.text());
  });
  page.on('dialog', async d => d.accept());
  // Input tables start folded: open one before using it.
  const openBlock = async (id) => {
    const d = await page.$(`[data-block="${id}"]`);
    if (!(await d.evaluate(e => e.open))) await page.click(`[data-block="${id}"] > summary`);
  };
  const addRow = async (id) => { await openBlock(id); await page.click(`[data-add="${id}"]`); return page.$$(`#${id} tr`); };
  const signIn = async (password) => {
    await page.waitForSelector('#login:not(.hidden)');
    await page.fill('#login-pw', password);
    await page.click('#login-go');
  };

  // 0. Sign-in: nothing shows until the password is right
  await page.goto(url);
  await page.waitForSelector('#login:not(.hidden)');
  await shot(page, '00_login');
  await signIn('wrong');
  await page.waitForSelector('#login-msg >> text=not right');
  await signIn(PASSWORD);
  await page.waitForSelector('text=Welcome');
  await shot(page, '00_welcome');

  // 1. Load (both permissions files ticked and merged)
  await page.click('nav >> text=Load exports');
  await page.waitForSelector('#go-load');
  for (const r of await page.$$('table tr')) {
    const t = await r.innerText();
    if (t.includes('accounts_by_group.xlsx')) { const cb = await r.$('.pick'); if (await cb.isChecked()) await cb.uncheck(); }
    if (t.includes('delinea_permissions')) {
      if (!(await (await r.$('.perm')).isChecked())) throw new Error('permissions file not pre-selected: ' + t);
      if (!(await (await r.$('.pick')).isChecked())) throw new Error('permissions file not ticked to load');
    }
  }
  // Ticking "Permissions file" must tick Load, never untick it
  {
    const r = (await page.$$('table tr'))[1];
    const pick = await r.$('.pick'), perm = await r.$('.perm');
    const was = [await pick.isChecked(), await perm.isChecked()];
    await pick.uncheck(); await perm.uncheck(); await perm.check();
    if (!(await pick.isChecked())) throw new Error('ticking Permissions file did not tick Load');
    await perm.uncheck();
    if (!(await pick.isChecked())) throw new Error('unticking Permissions file unticked Load');
    if (!was[0]) await pick.uncheck();
    if (was[1]) await perm.check();
  }
  if (!(await page.getAttribute('.perm', 'title'))) throw new Error('no tooltip on the Permissions file box');
  await shot(page, '01_load');
  await page.click('#go-load');
  await page.waitForSelector('#load-msg .msg.ok', { timeout: 10000 });
  const loadMsg = await page.innerText('#load-msg');
  console.log('LOAD:', loadMsg.replace(/\n/g, ' | '));
  if (!loadMsg.includes('delinea_export.csv: 8 records')) throw new Error('load failed');
  if (!loadMsg.includes('delinea_permissions_extra.csv')) throw new Error('second permissions file not merged');
  // load the same KeePass file again: the Overview must say it is the same content
  await page.click('nav >> text=Load exports');
  await page.waitForFunction(() => document.querySelector('#go-load') && !document.querySelector('#load-msg').textContent);
  for (const cb of await page.$$('.perm')) if (await cb.isChecked()) await cb.uncheck();
  for (const cb of await page.$$('.pick')) if (await cb.isChecked()) await cb.uncheck();
  for (const r of await page.$$('table tr')) if ((await r.innerText()).includes('keepass_export.xml')) await (await r.$('.pick')).check();
  await page.click('#go-load');
  await page.waitForSelector('#load-msg .msg.ok', { timeout: 10000 });

  // 2. Mapping rules, page by page
  await page.click('nav >> text=A. Directory sources');
  await page.waitForSelector('#dir-out table');
  if (await page.$eval('[data-block="t-dg"]', e => e.open)) throw new Error('input table not folded by default');
  let rows = await addRow('t-dg');
  await (await rows[rows.length - 1].$('[data-k=name]')).fill('Corporate AD');
  await (await rows[rows.length - 1].$('[data-k=match]')).fill('CORP');
  await (await rows[rows.length - 1].$('[data-k=search_in]')).fill('corp.example.com');
  await (await rows[rows.length - 1].$('[data-k=case]')).selectOption('upper');
  await page.click('#dir-preview');
  await page.waitForSelector('#dir-out >> text=Corporate AD');
  await shot(page, '02a_directory');
  await page.click('#save');
  await page.waitForSelector('#rules-msg .msg.ok');
  if ((await page.$eval('nav', e => getComputedStyle(e).position)) !== 'sticky') throw new Error('left nav does not stay in view');

  await page.click('#rules-next');                       // Next goes to the next sub-page, not to Review
  await page.waitForSelector('text=Safe from access groups');
  if (!(await page.innerText('h2')).includes('B. Permissions: Safes')) throw new Error('Next did not open B. Safes');
  if (await page.inputValue('#fallback') !== 'convention') throw new Error('folder naming is not the default');
  rows = await addRow('t-gr');
  await (await rows[rows.length - 1].$('[data-k=group]')).fill('CORP\\DBA-Team');
  await (await rows[rows.length - 1].$('[data-k=safe]')).fill('DB-Production-Privileged-Accounts');
  rows = await addRow('t-fr');
  await (await rows[rows.length - 1].$('[data-k=folder_prefix]')).fill('\\Linux');
  await (await rows[rows.length - 1].$('[data-k=safe]')).fill('UNIX:Servers');
  await page.waitForSelector('#t-fr .chk-msg');          // the forbidden ':' is flagged as you type
  console.log('SAFE CHECK:', await page.innerText('#t-fr .chk-msg'));
  await (await rows[rows.length - 1].$('[data-k=safe]')).fill('UNIX-Servers');
  if (await page.$('#t-fr .chk-msg')) throw new Error('warning stayed after fixing the name');
  if (!(await page.getAttribute('#s-cpm', 'title'))) throw new Error('no tooltip on the CPM field');
  await page.waitForSelector('#conv-folders input[data-folder]', { state: 'attached' });
  console.log('FOLDER CODES:', (await page.$$('#conv-folders input[data-folder]')).length);
  // a custom placeholder, used in the template
  await page.fill('#new-layer', 'region');
  await page.click('#add-layer');
  rows = await page.$$('#t-layer-region tr');
  await (await rows[1].$('[data-k=field]')).fill('address');
  await (await rows[1].$('[data-k=pattern]')).fill('corp\\.example\\.com$');
  await (await rows[1].$('[data-k=code]')).fill('HQ');
  await page.fill('#conv-template', '{region}-{folder}');
  await page.fill('#s-cpm', 'PasswordManager');
  await page.fill('#s-desc', 'Migrated from {folder}');
  await page.check('input[name=ret][value=versions]');
  await page.fill('#s-ver', '10');
  await page.click('#conv-preview');
  await page.waitForSelector('#conv-out >> text=HQ-');
  await shot(page, '02b_safes');
  await page.click('#save');
  await page.waitForSelector('#rules-msg .msg.ok');
  console.log('SAFES RULES:', await page.innerText('#rules-msg'));

  await page.click('nav >> text=B. Permissions: Safe members');
  await page.waitForSelector('#roles table', { state: 'attached' });
  await page.selectOption('#role-from', 'Read only');
  await page.click('#role-add');
  await page.fill('.role-name >> nth=-1', 'Helpdesk');
  await page.check('.role-perm[data-p="viewAuditLog"] >> nth=-1');
  await openBlock('t-pr');
  for (const r of await page.$$('#t-pr tr')) {
    const k = await r.$('[data-k=role]');
    if (k && (await k.inputValue()) === 'View') await (await r.$('[data-k=to]')).selectOption('Helpdesk');
  }
  await shot(page, '02c_members');
  await page.click('#save');
  await page.waitForSelector('#rules-msg .msg.ok');

  await page.click('nav >> text=C. Platforms');
  await page.waitForSelector('#t-pm', { state: 'attached' });
  await page.click('#save');
  await page.waitForSelector('#rules-msg .msg.ok');
  await page.click('nav >> text=D. Accounts');
  await page.waitForSelector('#an-t');
  await shot(page, '02d_accounts');
  await page.click('#save');
  await page.waitForSelector('#rules-msg .msg.ok');

  // 3B. Accounts & platforms
  await page.click('nav >> text=B. Accounts & platforms');
  await page.waitForSelector('#list table');
  await page.selectOption('#view', 'all');
  await page.waitForTimeout(500);
  console.log('ALL:', await page.innerText('#list p'));
  await shot(page, '03_review');
  await page.fill('#f-search', 'Vendor');
  await page.waitForTimeout(800);
  await page.check('.sel');
  await page.fill('#reason', 'finance asked');
  await page.fill('#a-safe', 'APP:Payments');
  await page.waitForSelector('#a-safe + .chk-msg');
  await page.click('[data-act=safe]');
  await page.waitForSelector('#act-msg .msg.ok');
  console.log('MOVE:', await page.innerText('#act-msg'));
  // no platform for one account
  await page.fill('#f-search', 'svc_sql');
  await page.waitForTimeout(800);
  await page.check('.sel >> nth=0');
  await page.fill('#a-plat', '(none)');
  await page.click('[data-act=platform]');
  await page.waitForSelector('#act-msg .msg.ok');
  await page.waitForSelector('#list >> text=no platform');
  await page.fill('#f-search', '');
  await page.selectOption('#view', 'errors');
  await page.waitForTimeout(800);
  console.log('ERRORS:', await page.innerText('#list p'));
  await page.check('#allmatch');
  await page.click('[data-act=exclude]');
  await page.waitForSelector('#act-msg .msg.ok');
  console.log('EXCLUDE:', await page.innerText('#act-msg'));
  await page.selectOption('#view', 'edited');
  await page.waitForTimeout(800);
  await page.click('tr.clickable >> nth=0');
  await page.waitForSelector('#drawer:not(.hidden)');
  await shot(page, '04_record');
  await page.click('#drawer >> text=Close');

  // 3A. Safes & Safe members: add one member to two Safes, then undo one of them
  await page.click('nav >> text=A. Safes & Safe members');
  await page.waitForSelector('text=Members (');
  const ticks = await page.$$('.s-sel');
  await ticks[0].check(); await ticks[1].check();
  await page.fill('#m-name', 'PAM-Auditors');
  await page.selectOption('#m-role', 'Read only');
  await page.fill('#m-reason', 'audit team');
  await page.click('#m-add');
  await page.waitForSelector('#m-msg .msg.ok');
  console.log('ADD MEMBER:', await page.innerText('#m-msg'));
  await page.waitForSelector('text=Your member changes (2)');
  await shot(page, '05_safes_bulk');
  await page.click('[data-undo="0"]');
  await page.waitForSelector('text=Your member changes (1)');
  const safesHtml = await page.content();
  if (!safesHtml.includes('Helpdesk')) throw new Error('custom role not used for any member');
  if (!safesHtml.includes('PasswordManager') || !safesHtml.includes('10 versions')) throw new Error('Safe settings missing');
  if (!safesHtml.includes('Corporate AD')) throw new Error('directory source not used');
  await shot(page, '05_safes');

  // 5. Output
  await page.click('nav >> text=Create upload files');
  await page.waitForSelector('#extract');
  await page.check('input[name=sec][value="1"]');
  await page.fill('#o-name', 'wave1');
  await page.click('#extract');
  await page.waitForSelector('#out-msg .msg.err');
  console.log('NO CONFIRM:', await page.innerText('#out-msg'));
  await page.fill('#confirm', 'INCLUDE SECRETS');
  await page.click('#extract');
  await page.waitForSelector('#out-msg .msg.ok');
  const extractMsg = await page.innerText('#out-msg');
  console.log('EXTRACT:', extractMsg.replace(/\n/g, ' | '));
  if (/ 0 members/.test(extractMsg)) throw new Error('no Safe members: permissions were not applied');
  if (!extractMsg.includes('FileCategories.csv') || !extractMsg.includes('PlatformProperties.csv')) throw new Error('category lists missing');
  await shot(page, '06_output');

  // Overview: boxes open their lists, repeated loads are marked
  await page.click('nav >> text=Overview');
  await page.waitForSelector('text=records loaded');
  if (!(await page.content()).includes('same content')) throw new Error('repeated load not marked');
  await shot(page, '07_overview');
  await page.click('.stat[data-view=errors]');
  await page.waitForSelector('#list table');
  if (await page.inputValue('#view') !== 'errors') throw new Error('errors box did not open the errors list');
  await page.click('nav >> text=Overview');
  await page.waitForSelector('text=records loaded');
  await page.click('.stat[data-view=review]');
  await page.waitForSelector('#list');
  if (await page.inputValue('#view') !== 'review') throw new Error('review box did not open the review list');

  // Activity log
  await page.click('nav >> text=Activity log');
  await page.waitForSelector('text=Your changes to accounts');
  await page.waitForSelector('text=By action');
  const [download] = await Promise.all([page.waitForEvent('download'), page.click('text=Export the activity log (CSV)')]);
  const csv = fs.readFileSync(await download.path(), 'utf8');
  if (!csv.includes('action') || !csv.includes('ingest')) throw new Error('activity export is empty');
  await shot(page, '08_activity');
  const html = await page.content();
  if (/P@ssw0rd|Kp!root|Fw#01admin/.test(html)) throw new Error('secret leaked into the page');

  // Lock, unlock, then end the session (database kept)
  await page.click('#lock');
  await page.waitForSelector('#login:not(.hidden)');
  if ((await page.innerText('#main')).trim()) throw new Error('data still visible while locked');
  if ((await page.innerText('#login-msg')).trim()) throw new Error('old wrong-password message still on the lock screen');
  await signIn('wrong again');
  await page.waitForSelector('#login-msg >> text=not right');
  await signIn(PASSWORD);
  await page.waitForSelector('#login', { state: 'hidden' });
  await page.click('#lock');
  await page.waitForSelector('#login:not(.hidden)');
  if ((await page.innerText('#login-msg')).trim()) throw new Error('wrong-password message came back on the next lock');
  await signIn(PASSWORD);
  await page.waitForSelector('#login', { state: 'hidden' });
  await page.click('#logout');
  await page.waitForSelector('#endbox:not(.hidden)');
  await shot(page, '09_end_session');
  await page.click('#end-go');
  await page.waitForSelector('#end-msg >> text=END SESSION');
  await page.fill('#end-confirm', 'END SESSION');
  await page.click('#end-go');
  await page.waitForSelector('text=Session ended');
  if (!(await page.content()).includes('still on disk')) throw new Error('end session message wrong');

  if (errors.length) throw new Error('JS errors: ' + errors.join('; '));
  console.log('PASS');
  await browser.close();
})().catch(e => { console.error('FAIL', e); process.exit(1); });
