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
  const url = log.match(/http:\/\/127\.0\.0\.1:\d+\/\?t=\S+/)[0];
  const shots = process.argv[3];
  const shot = async (page, name) => { if (shots) await page.screenshot({ path: `${shots}/${name}.png` }); };
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => {
    if (m.type() === 'error' && !/status of (400|401|423)/.test(m.text())) errors.push(m.text());
  });
  page.on('dialog', async d => d.message().includes('which Safe') ? d.accept('APP:Payments') : d.accept());
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
      if (await (await r.$('.pick')).isChecked()) throw new Error('permissions file ticked as an export');
    }
  }
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
  for (const cb of await page.$$('.pick')) if (await cb.isChecked()) await cb.uncheck();
  for (const cb of await page.$$('.perm')) if (await cb.isChecked()) await cb.uncheck();
  for (const r of await page.$$('table tr')) if ((await r.innerText()).includes('keepass_export.xml')) await (await r.$('.pick')).check();
  await page.click('#go-load');
  await page.waitForSelector('#load-msg .msg.ok', { timeout: 10000 });

  // 2. Mapping rules, page by page
  await page.click('nav >> text=A. Directory sources');
  await page.waitForSelector('#dir-out table');
  await page.click('[data-add="t-dg"]');
  let rows = await page.$$('#t-dg tr');
  await (await rows[rows.length - 1].$('[data-k=name]')).fill('Corporate AD');
  await (await rows[rows.length - 1].$('[data-k=match]')).fill('CORP');
  await (await rows[rows.length - 1].$('[data-k=search_in]')).fill('corp.example.com');
  await (await rows[rows.length - 1].$('[data-k=case]')).selectOption('upper');
  await page.click('#dir-preview');
  await page.waitForSelector('#dir-out >> text=Corporate AD');
  await shot(page, '02a_directory');
  await page.click('#save');
  await page.waitForSelector('#rules-msg .msg.ok');

  await page.click('nav >> text=B. Permissions: Safes');
  await page.waitForSelector('text=Safe from access groups');
  if (await page.inputValue('#fallback') !== 'convention') throw new Error('folder naming is not the default');
  await page.click('[data-add="t-gr"]');
  rows = await page.$$('#t-gr tr');
  await (await rows[rows.length - 1].$('[data-k=group]')).fill('CORP\\DBA-Team');
  await (await rows[rows.length - 1].$('[data-k=safe]')).fill('DB-Production-Privileged-Accounts');
  await page.click('[data-add="t-fr"]');
  rows = await page.$$('#t-fr tr');
  await (await rows[rows.length - 1].$('[data-k=folder_prefix]')).fill('\\Linux');
  await (await rows[rows.length - 1].$('[data-k=safe]')).fill('UNIX-Servers');
  await page.waitForSelector('#conv-folders input[data-folder]');
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
  await page.waitForSelector('#roles table');
  await page.selectOption('#role-from', 'Read only');
  await page.click('#role-add');
  await page.fill('.role-name >> nth=-1', 'Helpdesk');
  await page.check('.role-perm[data-p="viewAuditLog"] >> nth=-1');
  for (const r of await page.$$('#t-pr tr')) {
    const k = await r.$('[data-k=role]');
    if (k && (await k.inputValue()) === 'View') await (await r.$('[data-k=to]')).selectOption('Helpdesk');
  }
  await shot(page, '02c_members');
  await page.click('#save');
  await page.waitForSelector('#rules-msg .msg.ok');

  await page.click('nav >> text=C. Platforms');
  await page.waitForSelector('#t-pm');
  await page.click('#save');
  await page.waitForSelector('#rules-msg .msg.ok');
  await page.click('nav >> text=D. Accounts');
  await page.waitForSelector('#an-t');
  await shot(page, '02d_accounts');
  await page.click('#save');
  await page.waitForSelector('#rules-msg .msg.ok');

  // 3. Review
  await page.click('nav >> text=Review & change');
  await page.waitForSelector('#list table');
  await page.selectOption('#view', 'all');
  await page.waitForTimeout(500);
  console.log('ALL:', await page.innerText('#list p'));
  await shot(page, '03_review');
  await page.fill('#f-search', 'Vendor');
  await page.waitForTimeout(800);
  await page.check('.sel');
  await page.fill('#reason', 'finance asked');
  await page.click('[data-act=safe]');
  await page.waitForSelector('#act-msg .msg.ok');
  console.log('MOVE:', await page.innerText('#act-msg'));
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

  // 4. Safes
  await page.click('nav >> text=Safes & members');
  await page.waitForSelector('text=Members (');
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
