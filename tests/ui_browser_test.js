// End-to-end browser test of the Idira Migration Workbench UI (needs Node.js + Playwright).
//
//   IMW_UI_TEST_PASSWORD=test-pass IMW_UI_NO_OPEN=1 \
//     python -m imw ui -w <ws> --no-browser --insecure-plaintext-secrets > ui.log &
//   (copy samples/delinea_export.csv, delinea_permissions.csv, delinea_permissions_extra.csv, keepass_export.xml,
//    accounts_by_group.xlsx into <ws>/inbox first)
//   node tests/ui_browser_test.js ui.log [screenshot-folder]
const { chromium } = require('playwright');
const fs = require('fs');

const PASSWORD = process.env.IMW_UI_TEST_PASSWORD || 'test-pass';

(async () => {
  const log = fs.readFileSync(process.argv[2], 'utf8');
  const url = log.match(/https:\/\/127\.0\.0\.1:\d+\/\?t=\S+/)[0];
  const shots = process.argv[3];
  const shot = async (page, name) => { if (shots) await page.screenshot({ path: `${shots}/${name}.png` }); };
  const browser = await chromium.launch();
  // The certificate is self-signed for this computer; a real browser warns once (or not after --trust-cert).
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, ignoreHTTPSErrors: true });
  const errors = [];
  page.on('pageerror', e => { errors.push(e.message); console.log('PAGEERROR', e.stack); });
  page.on('console', m => {
    if (m.type() === 'error' && !/status of (400|401|423)/.test(m.text())) errors.push(m.text());
  });
  const DIALOGS = []; let DISMISS = false;
  page.on('dialog', async d => { DIALOGS.push(d.message()); if (DISMISS) { DISMISS = false; await d.dismiss(); } else await d.accept(); });
  // Input tables start folded: open one before using it.
  const openBlock = async (id) => {
    const d = await page.$(`[data-block="${id}"]`);
    if (!(await d.evaluate(e => e.open))) await page.click(`[data-block="${id}"] > summary`);
  };
  const addRow = async (id) => { await openBlock(id); await page.click(`[data-add="${id}"]`); return page.$$(`#${id} tr`); };
  // Only the step you are in shows its sub-pages: open the step first when needed.
  const navTo = async (id) => {
    const sub = page.locator(`nav button.sub[data-page="${id}"]`);
    if (await sub.count()) {
      if (!(await sub.isVisible())) await page.click(`nav button[data-group="${id.startsWith('rules') ? 'rules' : 'review'}"]`);
      await sub.click();
    } else await page.click(`nav button[data-page="${id}"]`);
  };
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
  await page.waitForTimeout(300); await shot(page, '00_login_error');
  await signIn(PASSWORD);
  await page.waitForSelector('#main h2 >> text=Welcome');   // the Overview, not a blank page
  if (await page.getAttribute('html', 'data-theme') !== 'dark') throw new Error('dark mode is not the default');
  await page.click('#theme');
  if (await page.getAttribute('html', 'data-theme') !== 'light') throw new Error('theme switch did not change to light');
  await shot(page, '00_welcome_light');
  await page.click('#theme');
  await shot(page, '00_welcome');

  // 1. Load (both permissions files ticked and merged)
  await page.click('nav >> text=Load exports');
  await page.waitForSelector('#go-load');
  for (const r of await page.$$('#main div.card table tr')) {
    const t = await r.innerText();
    if (t.includes('accounts_by_group.xlsx')) { const cb = await r.$('.pick'); if (await cb.isChecked()) await cb.uncheck(); }
    if (t.includes('delinea_permissions')) {
      if (!(await (await r.$('.perm')).isChecked())) throw new Error('permissions file not pre-selected: ' + t);
      if (!(await (await r.$('.pick')).isChecked())) throw new Error('permissions file not ticked to load');
    }
  }
  // Ticking "Permissions file" must tick Load, never untick it
  {
    const r = (await page.$$('#main div.card table tr'))[1];
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
  // Loaded files say so, and are no longer ticked to load again
  for (const r of await page.$$('#main div.card table tr')) {
    const t = await r.innerText();
    if (t.includes('keepass_export.xml')) {
      if (!/loaded/.test(t)) throw new Error('loaded file not marked as loaded: ' + t);
      if (await (await r.$('.pick')).isChecked()) throw new Error('loaded file still ticked to load');
    }
  }
  if (!(await page.$('#del-loaded'))) throw new Error('no button to securely delete the loaded exports');
  // load the same KeePass file again: the Overview must say it is the same content
  await page.click('nav >> text=Load exports');
  await page.waitForFunction(() => document.querySelector('#go-load') && !document.querySelector('#load-msg').textContent);
  for (const cb of await page.$$('.perm')) if (await cb.isChecked()) await cb.uncheck();
  for (const cb of await page.$$('.pick')) if (await cb.isChecked()) await cb.uncheck();
  for (const r of await page.$$('#main div.card table tr')) if ((await r.innerText()).includes('keepass_export.xml')) await (await r.$('.pick')).check();
  await page.click('#go-load');
  await page.waitForSelector('#load-msg .msg.ok', { timeout: 10000 });

  // 2. Mapping rules, page by page
  await navTo('rules-dir');
  await page.waitForSelector('#dir-out table');
  if (await page.$eval('[data-block="t-dg"]', e => e.open)) throw new Error('input table not folded by default');
  // Every column heading explains its field with an example; so does every cell
  {
    const cols = ['name', 'match', 'search_in', 'strip_domain', 'find', 'replace', 'add_prefix', 'add_suffix', 'case'];
    for (const k of ['match', 'search_in', 'find', 'replace', 'case']) {
      const tip = await page.$eval(`#t-dg th:nth-child(${cols.indexOf(k) + 1})`, e => e.title);
      if (!tip || tip.length < 40) throw new Error(`no explained tooltip on the ${k} heading`);
    }
  }
  if (!(await page.$('.explain >> text=How it works'))) throw new Error('directory sources page does not explain itself');
  if ((await page.$$eval('#dir-type option', os => os.map(o => o.value))).join() !== 'Group,User,Role') throw new Error('member types are not Group, User, Role');
  if (await page.inputValue('#dir-fallback') !== '') throw new Error('searchIn is not blank by default');
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

  if (!(await page.innerText('#rules-next')).includes('3. Review')) throw new Error('the last rules page does not lead to Review');
  await navTo('rules-safes');
  await page.waitForSelector('text=Safe from access groups');
  if (!(await page.innerText('h2')).includes('A. Safes')) throw new Error('A. Safes did not open');
  if (!(await page.isDisabled('#save'))) throw new Error('Save & apply enabled with nothing changed');
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
  // Codes start folded; so do the placeholders section and each placeholder inside it
  if (await page.$eval('[data-block="codes"]', e => e.open)) throw new Error('codes not folded by default');
  await openBlock('codes');
  if (await page.$eval('[data-block="layers-all"]', e => e.open)) throw new Error('placeholders not folded by default');
  console.log('PLACEHOLDERS:', await page.innerText('#layers-sum'));
  await openBlock('layers-all');
  if (await page.$eval('[data-block="layer-env"]', e => e.open)) throw new Error('{env} not folded by default');
  console.log('ENV:', (await page.innerText('[data-block="layer-env"] > summary')).replace(/\s+/g, ' '));
  // a custom placeholder, used in the template
  await page.fill('#new-layer', 'region');
  await page.click('#add-layer');
  if (!(await page.$eval('[data-block="layer-region"]', e => e.open))) throw new Error('new placeholder not opened');
  rows = await page.$$('#t-layer-region tr');
  await (await rows[1].$('[data-k=field]')).fill('address');
  await (await rows[1].$('[data-k=pattern]')).fill('corp\\.example\\.com$');
  await (await rows[1].$('[data-k=code]')).fill('HQ');
  await page.fill('#conv-template', '{region}-{folder}');
  await page.fill('#s-cpm', 'PasswordManager');
  await page.fill('#s-desc', 'Migrated from {folder}');
  await page.check('input[name=ret][value=versions]');
  await page.fill('#s-ver', '10');
  // The preview at the bottom follows the settings above live, before Save & apply, with each Safe's CPM.
  await page.waitForSelector('#conv-out >> text=HQ-');
  await page.waitForSelector('#conv-out td.chg >> text=PasswordManager');
  await page.fill('#s-cpm', 'CPM-Live');
  await page.waitForSelector('#conv-out td >> text=CPM-Live');
  await page.fill('#s-cpm', 'PasswordManager');
  await page.waitForSelector('#conv-out td >> text=PasswordManager');
  await page.check('#pv-changed');
  if (!(await page.$$('#conv-out tr')).length) throw new Error('changed-only preview filter shows nothing');
  await page.uncheck('#pv-changed');
  await page.$eval('#preview-card', e => e.scrollIntoView());
  await shot(page, '02b_safes');
  await page.click('#save');
  await page.waitForSelector('#rules-msg .msg.ok');
  console.log('SAFES RULES:', await page.innerText('#rules-msg'));
  // Removing a placeholder is a change: Save & apply must come back on (round 3 audit)
  await page.fill('#new-layer', 'zone');
  await page.click('#add-layer');
  await page.$eval('#rules-msg', e => e.innerHTML = ''); await page.click('#save'); await page.waitForSelector('#rules-msg .msg.ok');
  if (!(await page.isDisabled('#save'))) throw new Error('Save still enabled right after saving');
  await openBlock('layer-zone');
  await page.click('[data-block="layer-zone"] .l-del');
  if (await page.isDisabled('#save')) throw new Error('Save stays disabled after removing a placeholder');
  await page.$eval('#rules-msg', e => e.innerHTML = ''); await page.click('#save'); await page.waitForSelector('#rules-msg .msg.ok');

  await page.click('#rules-next');                       // Next goes to the next sub-page
  await page.waitForSelector('#roles table', { state: 'attached' });
  if (!(await page.innerText('h2')).includes('B. Safe members')) throw new Error('Next did not open B. Safe members');
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
  // Deleting a custom role is a change: Save & apply must come back on (round 3 audit)
  await page.click('#role-add');
  await page.fill('.role-name >> nth=-1', 'Temp');
  await page.$eval('#rules-msg', e => e.innerHTML = ''); await page.click('#save'); await page.waitForSelector('#rules-msg .msg.ok');
  const rolesBefore = await page.locator('.role-name').count();
  await page.click('#roles [data-del] >> nth=-1');
  if (await page.isDisabled('#save')) throw new Error('Save stays disabled after deleting a custom role');
  await page.$eval('#rules-msg', e => e.innerHTML = ''); await page.click('#save'); await page.waitForSelector('#rules-msg .msg.ok');
  if (await page.locator('.role-name').count() !== rolesBefore - 1 || await page.$('.role-name[value="Temp"]'))
    throw new Error('deleted custom role came back');

  await navTo('rules-platforms');
  await page.waitForSelector('#t-pm', { state: 'attached' });
  if (!(await page.$('.explain >> text=How a platform is chosen'))) throw new Error('platforms page does not explain rules vs record type');
  // unsaved changes: leaving asks first, and Cancel stays on the page
  await page.fill('#defplat', 'WinServerLocal');
  DISMISS = true;
  await navTo('rules-accounts');
  if (!/not saved/.test(DIALOGS[DIALOGS.length - 1] || '')) throw new Error('no unsaved-changes warning when leaving a page');
  if (!(await page.innerText('h2')).includes('C. Platforms')) throw new Error('Cancel on the unsaved warning still left the page');
  await page.fill('#defplat', '');
  await shot(page, '02e_platforms');
  await page.click('#save');
  await page.waitForSelector('#rules-msg .msg.ok');
  await navTo('rules-accounts');
  await page.waitForSelector('#an-t');
  await page.check('input[name=an-mode][value=none]');
  if (!(await page.isDisabled('#an-t'))) throw new Error('name pattern still editable with names left to Privilege Cloud');
  await shot(page, '02d_accounts');
  await page.check('input[name=an-mode][value=pattern]');
  await page.click('#save');
  await page.waitForSelector('#rules-msg .msg.ok');

  // 3B. Accounts & platforms
  await navTo('review');
  await page.waitForSelector('#list table');
  await page.selectOption('#view', 'all');
  await page.waitForTimeout(500);
  console.log('ALL:', await page.innerText('#list p'));
  await shot(page, '03_review');
  // Approve an account that needs a look: it keeps the label, gets a green tick, and loses it once it changes.
  await page.selectOption('#view', 'review');
  await page.waitForTimeout(500);
  if (!(await page.innerText('#list thead')).includes('Why it needs a look')) throw new Error('no reason column on the review list');
  if ((await page.innerText('#list tbody')).includes('no access groups')) throw new Error('Safe-level note shown on an account');
  await page.check('.sel');
  await page.click('[data-act=approve]');
  await page.waitForSelector('#act-msg >> text=Approved 1 account');
  await page.waitForSelector('#list .approved');
  console.log('APPROVE:', await page.innerText('#act-msg'));
  await shot(page, '03_review_approved');
  await page.click('#list tr.clickable:has(.approved) td:nth-child(2)');
  await page.waitForSelector('#drawer #ra-unapprove');
  await shot(page, '04_record_approved');
  await page.click('[data-close-drawer]');
  await page.$eval('#act-msg', e => e.innerHTML = '');
  await page.selectOption('#view', 'all');
  await page.waitForTimeout(500);
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
  if (await page.isVisible('#acts')) throw new Error('actions shown with nothing ticked');
  await page.click('#allmatch-link');
  await page.click('[data-act=exclude]');
  await page.waitForSelector('#act-msg .msg.ok');
  console.log('EXCLUDE:', await page.innerText('#act-msg'));
  // leave one account's name to Privilege Cloud
  await page.selectOption('#view', 'all');
  await page.fill('#f-search', 'svc_backup');
  await page.waitForTimeout(800);
  await page.check('.sel >> nth=0');
  if (!(await page.isVisible('[data-act=noname]'))) await page.click('#acts details > summary');
  await page.click('[data-act=noname]');
  await page.waitForSelector('#act-msg .msg.ok');
  await page.waitForSelector('#list >> text=(named by Privilege Cloud)');
  await page.fill('#f-search', '');
  await page.selectOption('#view', 'edited');
  await page.waitForTimeout(800);
  await page.click('tr.clickable >> nth=0');
  await page.waitForSelector('#drawer:not(.hidden)');
  await shot(page, '04_record');
  await page.click('#drawer >> text=Close');
  // edit one account in its panel: platform and name, then undo the platform
  await page.selectOption('#view', 'all');
  await page.fill('#f-search', 'web01');
  await page.waitForTimeout(800);
  await page.click('tr.clickable >> nth=0');
  await page.waitForSelector('#ra-plat');
  await page.fill('#ra-plat', 'UnixSSHKeys');
  await page.fill('#ra-name', 'web-service-account');
  await page.fill('#ra-reason', 'checked with app team');
  await page.click('#ra-save');
  await page.waitForSelector('#ra-msg .msg.ok');
  if (await page.inputValue('#ra-plat') !== 'UnixSSHKeys') throw new Error('platform not saved from the account panel');
  await page.waitForSelector('#list >> text=web-service-account');
  await shot(page, '04_account_panel');
  await page.click('#drawer [data-undo-field="platform_id"]');
  await page.waitForSelector('#ra-msg >> text=Undone');
  if (await page.inputValue('#ra-plat') === 'UnixSSHKeys') throw new Error('undo did not hand the platform back to the rules');
  console.log('ACCOUNT PANEL: platform back to', await page.inputValue('#ra-plat'));
  // "open <Safe> in Safes & members" with unsaved changes: Cancel stays and opens nothing (round 3 audit)
  await page.fill('#ra-plat', 'SomethingElse');
  await page.$eval('#ra-open-safe', a => { a.closest('details').open = true; });
  DISMISS = true;
  await page.click('#ra-open-safe');
  if (await page.evaluate(() => PAGE) === 'review-safes') throw new Error('Cancel on the unsaved warning still left the account');
  if (await page.evaluate(() => SAFES.panel)) throw new Error('Cancelled link still set the Safe panel');
  await page.click('#drawer >> text=Close');
  await page.fill('#f-search', '');

  // 3A. Safes & Safe members: add one member to two Safes, then undo one of them
  await navTo('review-safes');
  await page.waitForSelector('text=Members (');
  // clicking a Safe shows its members (in a panel on this page), not its accounts
  {
    const first = await page.$('[data-members-of="UNIX-Servers"]');
    await first.click();
    await page.waitForSelector('#drawer:not(.hidden) >> text=Safe UNIX-Servers');
    if (!(await page.innerText('h2')).includes('Safes & members')) throw new Error('Safe click left the page');
    const n = (await page.$$('#drawer [data-open-person]')).length;
    console.log('SAFE CLICK: UNIX-Servers has', n, 'members');
    if (n < 2) throw new Error('Safe panel does not list its members');
    await shot(page, '05_safe_panel');
    // change one member's role on this Safe from the panel
    await page.selectOption('#drawer .pr-role >> nth=0', 'Read only');
    await page.waitForSelector('#panel-msg .msg.ok');
    // open a member from the Safe panel: its Safes, editable values
    await page.click('#drawer [data-open-person] >> nth=0');
    await page.waitForSelector('#pe-name');
    console.log('MEMBER PANEL:', (await page.innerText('#drawer h3')));
    await page.fill('#pe-name', 'PAM-Unix-Admins');
    await page.selectOption('#pe-type', 'Role');
    await page.fill('#pe-dir', '');
    await page.click('#pe-save');
    await page.waitForSelector('#panel-msg .msg.ok');
    await page.waitForSelector('#people-table >> text=PAM-Unix-Admins', { state: 'attached' });
    await shot(page, '05_member_panel');
    await page.click('#panel-close');
    // every member in the list is clickable, including members on no Safe
    await page.click('[data-tab=members]');
    const rowsAll = (await page.$$('#people-table tr[data-person]')).length;
    await page.check('#p-nosafe');
    const noSafe = (await page.$$('#people-table tr[data-person]:not(.hidden)')).length;
    console.log('MEMBERS:', rowsAll, 'listed,', noSafe, 'on no Safe');
    if (noSafe) {
      await page.click('#people-table tr[data-person]:not(.hidden) >> nth=0');
      await page.waitForSelector('#drawer >> text=On no Safe');
      await page.click('#panel-close');
    }
    await page.uncheck('#p-nosafe');
    await page.click('[data-tab=safes]');
  }
  if ((await page.$$eval('#m-type option', os => os.map(o => o.value))).join() !== 'Group,User,Role') throw new Error('member types are not Group, User, Role');
  if (await page.inputValue('#m-dir') !== '') throw new Error('searchIn not blank by default');
  if (await page.isVisible('#s-acts')) throw new Error('member actions shown with no Safe ticked');
  const ticks = await page.$$('.s-sel');
  await ticks[0].check(); await ticks[1].check();
  await page.fill('#m-name', 'PAM-Auditors');
  await page.selectOption('#m-role', 'Read only');
  await page.fill('#m-reason', 'audit team');
  await page.click('#m-add');
  await page.waitForSelector('#m-msg .msg.ok');
  console.log('ADD MEMBER:', await page.innerText('#m-msg'));
  await page.waitForSelector('text=Your member changes (4)');
  await shot(page, '05_safes_bulk');
  await page.click('#member-edits > summary');
  await page.click('[data-undo="0"]');
  await page.waitForSelector('text=Your member changes (3)');
  const safesHtml = await page.content();
  if (!safesHtml.includes('Helpdesk')) throw new Error('custom role not used for any member');
  if (!safesHtml.includes('PasswordManager') || !safesHtml.includes('10 versions')) throw new Error('Safe settings missing');
  if (!safesHtml.includes('corp.example.com')) throw new Error('directory source (searchIn) not used');
  await shot(page, '05_safes');

  // 5. Output
  await navTo('output');
  await page.waitForSelector('#extract');
  if (!/^\d{4}-\d{2}-\d{2}-all-dryrun/.test(await page.inputValue('#o-name'))) throw new Error('no ready-made output name');
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

  // Overview: steps with what to do next, and the count tiles that open their lists; loaded files are on the Load page
  await navTo('overview');
  await page.waitForSelector('text=Steps');
  if (!(await page.$('.security-notice'))) throw new Error('security notice missing from the Overview');
  if (await page.$eval('.security-notice', e => e.open)) throw new Error('security notice not folded on the Overview');
  await shot(page, '07_overview');
  await page.click('.stat[data-view=errors]');
  await page.waitForSelector('#list table');
  if (await page.inputValue('#view') !== 'errors') throw new Error('errors box did not open the errors list');
  if (!(await page.isVisible('.floatbar >> text=Next: 4. Create upload files'))) throw new Error('Accounts page has no floating Next');
  await navTo('output');
  await page.waitForSelector('text=Ready check');
  await page.click('.stat[data-view=review]');
  await page.waitForSelector('#list');
  if (await page.inputValue('#view') !== 'review') throw new Error('review box did not open the review list');
  await page.click('.floatbar >> text=Next: 4. Create upload files');
  await page.waitForSelector('#main h2 >> text=4. Create upload files');
  await navTo('load');
  await page.waitForSelector('#loaded-files');
  if (!(await page.content()).includes('same content')) throw new Error('repeated load not marked');
  await shot(page, '01_load_after');

  // Save & apply / Next float at the bottom of the window; the down arrow shows only while there is more below
  await navTo('rules-safes');
  await page.waitForSelector('.floatbar #save');
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(200);
  const fb = await page.$eval('.floatbar', e => { const r = e.getBoundingClientRect(); return { bottom: r.bottom, pos: getComputedStyle(e).position }; });
  if (fb.pos !== 'fixed' || Math.abs(fb.bottom - 900) > 1) throw new Error('Save & apply bar is not at the bottom of the window: ' + JSON.stringify(fb));
  const more = await page.evaluate(() => Math.max(...[...document.querySelectorAll('#main > :not(.floatbar)')].map(e => e.getBoundingClientRect().bottom)) > innerHeight - document.querySelector('.floatbar').offsetHeight + 4);
  if (more !== await page.isVisible('#more-below')) throw new Error('down arrow shown/hidden wrongly');
  await shot(page, '08_floatbar');
  if (more) {
    await page.click('#more-below'); await page.waitForTimeout(600);
    if (await page.evaluate(() => scrollY) === 0) throw new Error('down arrow did not scroll');
    await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight)); await page.waitForTimeout(200);
    if (await page.isVisible('#more-below')) throw new Error('down arrow still shown at the bottom');
  }

  // Rename one Safe and change its settings directly; Undo puts back the rules' values
  await navTo('review-safes');
  await page.waitForSelector('#safes-table');
  const firstSafe = await page.$eval('#safes-table [data-members-of]', a => a.dataset.membersOf);
  await page.click(`#safes-table [data-members-of="${firstSafe}"]`);
  await page.click('#drawer details.edit-block > summary');
  await page.fill('#sv-name', 'X-RENAMED-BY-ME');
  await page.fill('#sv-desc', 'Moved by the test');
  await page.fill('#sv-cpm', 'PasswordManager');
  await page.selectOption('#sv-keep-kind', 'versions'); await page.fill('#sv-keep', '12');
  await page.selectOption('#sv-purge', 'true');
  await page.click('#sv-save');
  await page.waitForSelector('#sv-msg .msg.ok');
  const row = await page.innerText('#safes-table tr[data-name="x-renamed-by-me"]');
  if (!/Moved by the test/.test(row) || !/PasswordManager/.test(row) || !/12 versions/.test(row) || !/changed by you/.test(row))
    throw new Error('Safe rename/settings not applied: ' + row);
  if (await page.$(`#safes-table tr[data-name="${firstSafe.toLowerCase()}"]`)) throw new Error('old Safe name still listed');
  await page.waitForSelector('text=Your Safe changes (1)');
  await shot(page, '09_safe_settings');
  await page.click('#sv-undo');
  await page.waitForSelector(`#safes-table tr[data-name="${firstSafe.toLowerCase()}"]`);
  if (await page.$('text=Your Safe changes')) throw new Error('Safe change not undone');

  // Rename one Safe into another: the other keeps its own settings key; Split back out undoes it (round 3 audit)
  {
    const names = await page.$$eval('#safes-table [data-members-of]', as => as.map(a => a.dataset.membersOf));
    const [sa, sb] = names;
    await page.click(`#safes-table [data-members-of="${sa}"]`);
    await page.click('#drawer details.edit-block > summary');
    await page.fill('#sv-name', sb);
    await page.click('#sv-save');
    await page.waitForSelector('#drawer [data-split]');
    if (await page.$(`#safes-table tr[data-name="${sa.toLowerCase()}"]`)) throw new Error('merged Safe still listed');
    if (!(await page.$eval('#drawer details.edit-block', e => e.open))) await page.click('#drawer details.edit-block > summary');
    if (await page.inputValue('#sv-name') !== sb) throw new Error('merged Safe panel shows the wrong name');
    await page.fill('#sv-desc', 'Own description of B');
    await page.$eval('#sv-msg', e => e.innerHTML = '');
    await page.click('#sv-save');
    await page.waitForSelector('#sv-msg .msg.ok');
    const keys = await page.evaluate(() => SAFES.data.safe_overrides.map(o => o.key).sort());
    if (JSON.stringify(keys) !== JSON.stringify([sa.toLowerCase(), sb.toLowerCase()].sort()))
      throw new Error('settings of the merged Safe saved under the wrong key: ' + keys);
    await shot(page, '09b_safe_merged');
    await page.click(`#drawer [data-split="${sa}"]`);
    await page.waitForSelector('#sv-msg >> text=a Safe of its own again');
    if (!(await page.$(`#safes-table tr[data-name="${sa.toLowerCase()}"]`))) throw new Error('Split back out did not bring back ' + sa);
    const rowB = await page.innerText(`#safes-table tr[data-name="${sb.toLowerCase()}"]`);
    if (!/Own description of B/.test(rowB)) throw new Error('splitting A out lost B\'s own settings: ' + rowB);
    if (!(await page.$eval('#drawer details.edit-block', e => e.open))) await page.click('#drawer details.edit-block > summary');
    await page.$eval('#sv-msg', e => e.innerHTML = '');
    await page.click('#sv-undo');
    await page.waitForSelector('#sv-msg >> text=Back to what the rules give', { state: 'attached' });
    if (await page.$('text=Your Safe changes')) throw new Error('merge test left Safe changes behind');
    await page.click('#drawer >> text=Close');
  }

  // Activity log
  await navTo('activity');
  await page.waitForSelector('text=Your changes to accounts');
  await page.waitForSelector('text=Latest entries');
  if (!(await page.innerText('#main')).includes('Loaded keepass_export.xml')) throw new Error('log entries not written as sentences');
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
  if (await page.isVisible('#end-confirm')) throw new Error('typing asked for without deleting the database');
  await page.check('#end-del');                          // deleting the database needs DELETE DB typed
  await page.click('#end-go');
  await page.waitForSelector('#end-msg >> text=DELETE DB');
  await page.uncheck('#end-del');
  await page.click('#end-go');                           // ending alone is one click
  await page.waitForSelector('text=Session ended');
  if (!(await page.content()).includes('still on disk')) throw new Error('end session message wrong');

  console.log('UNSAVED WARNINGS:', DIALOGS.filter(m => /not saved/.test(m)).length);
  if (errors.length) throw new Error('JS errors: ' + errors.join('; '));
  console.log('PASS');
  await browser.close();
})().catch(e => { console.error('FAIL', e); process.exit(1); });
