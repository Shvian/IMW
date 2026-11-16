// Browser test of the Delinea reports flow: Add files recognises each report, Users to decide, Review & create.
//
//   copy samples/delinea_reports/*.csv into <ws>/inbox, then
//   IMW_UI_TEST_PASSWORD=test-pass IMW_UI_NO_OPEN=1 \
//     python -m imw ui -w <ws> --no-browser --insecure-plaintext-secrets > ui.log &
//   node tests/ui_browser_reports_test.js ui.log [screenshot-folder]
const { chromium } = require('playwright');
const fs = require('fs');

const PASSWORD = process.env.IMW_UI_TEST_PASSWORD || 'test-pass';

(async () => {
  const log = fs.readFileSync(process.argv[2], 'utf8');
  const url = log.match(/https:\/\/127\.0\.0\.1:\d+\/\?t=\S+/)[0];
  const shots = process.argv[3];
  const shot = async (page, name) => { if (shots) await page.screenshot({ path: `${shots}/${name}.png`, fullPage: true }); };
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, ignoreHTTPSErrors: true });
  const errors = [];
  page.on('pageerror', e => { errors.push(e.message); console.log('PAGEERROR', e.stack); });
  page.on('console', m => { if (m.type() === 'error' && !/status of (400|401|423)/.test(m.text())) errors.push(m.text()); });
  page.on('dialog', d => d.accept());
  const navTo = async (id) => {
    const sub = page.locator(`nav button.sub[data-page="${id}"]`);
    if (await sub.count()) {
      if (!(await sub.isVisible())) {
        await page.click(`nav button[data-group="${await page.evaluate(p => NAV_GROUP[p], id)}"]`);
        if (await page.evaluate(() => PAGE) === id) return;   // the group opened on this page already
      }
      await sub.click();
    } else await page.click(`nav button[data-page="${id}"]`);
  };

  await page.goto(url);
  await page.waitForSelector('#login:not(.hidden)');
  await page.fill('#login-pw', PASSWORD);
  await page.click('#login-go');
  await page.waitForSelector('#main h2 >> text=Welcome');
  // Five steps in the menu, Activity log off it
  const steps = await page.$$eval('#nav > button:not(.sub)', bs => bs.map(b => b.innerText.replace(/\s+/g, ' ').trim()));
  console.log('MENU:', steps.join(' | '));
  if (steps.join('|') !== '⌂ Overview|1 Add files|2 Platforms|3 Safes|4 Members|5 Review & create') throw new Error('menu is not the five steps: ' + steps);

  // 1. Add files: every report recognised
  await navTo('load');
  await page.waitForSelector('#go-load');
  const want = { 'secrets-export.csv': 'accounts', 'allsecrets.csv': 'templates', 'lauserslist.csv': 'users',
    'whatfolderpermissionsexistforgroups.csv': 'permissions', 'whatfolderscanalluserssee.csv': 'permissions',
    'lagroups.csv': 'skip', 'secret-template-list.csv': 'skip', 'whatroleassignmentsexist.csv': 'skip',
    'whatrolepermissionassignmentsexist.csv': 'skip' };
  for (const r of await page.$$('#main table tr')) {
    const sel = await r.$('.kind'); if (!sel) continue;
    const name = (await (await r.$('td:nth-child(2)')).innerText()).trim();
    const got = await sel.inputValue();
    if (want[name] !== got) throw new Error(`${name} recognised as ${got}, not ${want[name]}`);
    if ((await (await r.$('.pick')).isChecked()) !== (got !== 'skip')) throw new Error(`${name}: wrong Load tick`);
  }
  const checklist = await page.innerText('.checklist');
  console.log('CHECKLIST:', checklist.replace(/\n/g, ' | '));
  await shot(page, 'r1_add_files');
  await page.click('#go-load');
  await page.waitForSelector('#load-msg .msg.ok', { timeout: 10000 });
  const loadMsg = await page.innerText('#load-msg');
  console.log('LOAD:', loadMsg.replace(/\n/g, ' | '));
  for (const t of ['secrets-export.csv: 6 accounts', 'allsecrets.csv: 5 rows', 'lauserslist.csv: 2 rows', '3 users from the users report'])
    if (!loadMsg.includes(t)) throw new Error('load message lacks ' + t);
  if ((await page.$$('.checklist li.ok')).length !== 4) throw new Error('checklist not complete after loading');
  await shot(page, 'r1_add_files_loaded');

  // Overview names the decision to make
  await navTo('overview');
  await page.waitForSelector('.steps');
  const ov = await page.innerText('.steps');
  if (!/3 users may get their access through a group/.test(ov)) throw new Error('Overview does not name the users to decide: ' + ov);
  await shot(page, 'r2_overview');

  // 2. Platforms: templates from allsecrets.csv
  await navTo('rules-platforms');
  await page.waitForFunction(() => /Web Password/.test(document.querySelector('#pv-out')?.innerText || ''), null, { timeout: 10000 }).catch(() => {});
  const pv = await page.innerText('#pv-out');
  if (!pv.includes('Web Password') || !pv.includes('Unix Account (SSH)')) throw new Error('templates from allsecrets.csv not in the platforms preview: ' + pv + ' / ' + await page.innerText('#pv-state') + ' / ' + await page.innerText('h2'));
  await shot(page, 'r3_platforms');

  // 4. Members · Users to decide
  await navTo('members-decide');
  await page.waitForSelector('#decide-table');
  if ((await page.$$('#decide-table .d-sel')).length !== 3) throw new Error('not 3 users to decide');
  if (!(await page.innerText('#decide-table')).includes('jane.smith@corp.example.com')) throw new Error('UPN not shown');
  await shot(page, 'r4_users_to_decide');
  await page.click('.g-dec[data-g="Unix Team"][data-d="exclude"]');
  await page.waitForSelector('#d-msg .msg.ok');
  if ((await page.$$('#decide-table .d-sel')).length !== 1) throw new Error('Leave all out did not decide the Unix Team users');
  await page.check('#decide-table .d-sel');
  await page.fill('#d-reason', 'owns the web portal');
  await page.click('#d-inc');
  try { await page.waitForSelector('#d-msg >> text=include', { timeout: 5000 }); } catch (e) { await shot(page, 'r4_fail'); throw new Error('include failed: ' + await page.innerText('#main')); }
  if (await page.$('#decide-table .d-sel')) throw new Error('a user is still undecided');
  await page.selectOption('#d-show', 'all');
  await page.waitForSelector('#decide-table .d-sel');
  await shot(page, 'r4_users_decided');

  // 5. Review & create: Jane is a member with her UPN, Bob as a direct user
  await navTo('review-safes');
  await page.waitForSelector('#safes-table');
  await page.click('.tabs [data-tab="members"]');
  const members = await page.innerText('#main');
  for (const t of ['jane.smith@corp.example.com', 'bob.jones@corp.example.com']) if (!members.includes(t)) throw new Error('missing member ' + t);
  if (members.includes('Nobody Known')) throw new Error('a user left out is still listed');
  await shot(page, 'r5_members');
  await navTo('output');
  await page.waitForSelector('#extract');
  if ((await page.innerText('#main')).includes('still need a decision')) throw new Error('undecided warning after deciding everyone');
  await page.click('#extract');
  await page.waitForSelector('#out-msg .msg.ok', { timeout: 10000 });
  const out = await page.innerText('#out-msg');
  console.log('EXTRACT:', out.replace(/\n/g, ' | '));
  if (!out.includes('Users_To_Decide.csv')) throw new Error('Users_To_Decide.csv not written');
  await shot(page, 'r6_create');

  if (errors.length) throw new Error('page errors: ' + errors.join('; '));
  await browser.close();
  console.log('PASS');
})().catch(e => { console.error('FAIL', e); process.exit(1); });
