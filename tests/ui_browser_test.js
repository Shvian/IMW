// End-to-end browser test of the pam2pc UI (needs Node.js + Playwright).
//
//   python -m pam2pc ui -w <ws> --no-browser --insecure-plaintext-secrets > ui.log &
//   (copy samples/delinea_export.csv, delinea_permissions.csv, keepass_export.xml,
//    accounts_by_group.xlsx into <ws>/inbox first)
//   node tests/ui_browser_test.js ui.log [screenshot-folder]
const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
  const log = fs.readFileSync(process.argv[2], 'utf8');
  const url = log.match(/http:\/\/127\.0\.0\.1:\d+\/\?t=\S+/)[0];
  const shots = process.argv[3];
  const shot = async (page, name) => { if (shots) await page.screenshot({ path: `${shots}/${name}.png` }); };
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => { if (m.type() === 'error' && !m.text().includes('status of 400')) errors.push(m.text()); });
  page.on('dialog', async d => d.message().includes('which Safe') ? d.accept('APP:Payments') : d.accept());

  await page.goto(url);
  await page.waitForSelector('text=Welcome');
  await shot(page, '00_welcome');

  // 1. Load
  await page.click('nav >> text=Load exports');
  await page.waitForSelector('#go-load');
  for (const r of await page.$$('table tr')) {
    const t = await r.innerText();
    if (t.includes('accounts_by_group.xlsx')) { const cb = await r.$('.pick'); if (await cb.isChecked()) await cb.uncheck(); }
    if (t.includes('delinea_permissions.csv')) {
      if (!(await (await r.$('input[name=perm]')).isChecked())) throw new Error('permissions file not pre-selected');
      if (await (await r.$('.pick')).isChecked()) throw new Error('permissions file ticked as an export');
    }
  }
  await shot(page, '01_load');
  await page.click('#go-load');
  await page.waitForSelector('#load-msg .msg.ok', { timeout: 10000 });
  console.log('LOAD:', (await page.innerText('#load-msg')).replace(/\n/g, ' | '));
  if (!(await page.innerText('#load-msg')).includes('delinea_export.csv: 8 records')) throw new Error('load failed');

  // 2. Rules
  await page.click('text=Next: mapping rules');
  await page.waitForSelector('text=Safe from access groups');
  await page.click('[data-add="t-gr"]');
  let rows = await page.$$('#t-gr tr');
  await (await rows[rows.length - 1].$('[data-k=group]')).fill('CORP\\DBA-Team');
  await (await rows[rows.length - 1].$('[data-k=safe]')).fill('DB-Production-Privileged-Accounts');
  await page.click('[data-add="t-fr"]');
  rows = await page.$$('#t-fr tr');
  await (await rows[rows.length - 1].$('[data-k=folder_prefix]')).fill('\\Linux');
  await (await rows[rows.length - 1].$('[data-k=safe]')).fill('UNIX-Servers');
  await page.selectOption('#fallback', 'folder_path');
  await shot(page, '02_rules');
  await page.click('#save');
  await page.waitForSelector('#rules-msg .msg.ok');
  console.log('RULES:', await page.innerText('#rules-msg'));

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

  await page.click('nav >> text=Overview');
  await page.waitForSelector('text=records loaded');
  await shot(page, '07_overview');
  await page.click('nav >> text=Activity log');
  await page.waitForSelector('text=Your changes to accounts');
  const html = await page.content();
  if (/P@ssw0rd|Kp!root|Fw#01admin/.test(html)) throw new Error('secret leaked into the page');
  if (errors.length) throw new Error('JS errors: ' + errors.join('; '));
  console.log('PASS');
  await browser.close();
})().catch(e => { console.error('FAIL', e); process.exit(1); });
