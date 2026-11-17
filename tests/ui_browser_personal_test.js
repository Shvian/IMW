// Browser test of personal Safes: 2. Mapping rules · A. Safes offers to mark \Personal Folders, and Save & apply names them after the person.
//
//   copy samples/personal_safes/*.csv and samples/delinea_reports/lauserslist.csv into <ws>/inbox, then
//   IMW_UI_TEST_PASSWORD=test-pass IMW_UI_NO_OPEN=1 \
//     python -m imw ui -w <ws> --no-browser --insecure-plaintext-secrets > ui.log &
//   node tests/ui_browser_personal_test.js ui.log [screenshot-folder]
const { chromium } = require('playwright');
const fs = require('fs');

const PASSWORD = process.env.IMW_UI_TEST_PASSWORD || 'test-pass';

(async () => {
  const url = fs.readFileSync(process.argv[2], 'utf8').match(/https:\/\/127\.0\.0\.1:\d+\/\?t=\S+/)[0];
  const shots = process.argv[3];
  const shot = async (page, name) => { if (shots) await page.screenshot({ path: `${shots}/${name}.png`, fullPage: true }); };
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, ignoreHTTPSErrors: true });
  const errors = [];
  page.on('pageerror', e => { errors.push(e.message); console.log('PAGEERROR', e.stack); });
  page.on('console', m => { if (m.type() === 'error' && !/status of (400|401|423)/.test(m.text())) errors.push(m.text()); });
  page.on('dialog', d => d.accept());

  await page.goto(url);
  await page.waitForSelector('#login:not(.hidden)');
  await page.fill('#login-pw', PASSWORD);
  await page.click('#login-go');
  await page.waitForSelector('#main h2');

  await page.click('nav button[data-page="load"]');
  await page.waitForSelector('#go-load');
  await page.click('#go-load');
  await page.waitForSelector('#load-msg .msg.ok', { timeout: 10000 });

  // Before: the person's folder is abbreviated like any other folder
  await page.click('nav button[data-page="rules-safes"]');
  await page.waitForSelector('.ps-mark');
  await page.waitForFunction(() => /PRS-FLD-JANE/.test(document.querySelector('#pv-out')?.innerText || ''), null, { timeout: 10000 });
  await shot(page, 'p1_before');
  await page.click('.ps-mark[data-folder="\\\\Personal Folders"]');
  await page.waitForFunction(() => /P-jane\.smith/.test(document.querySelector('#pv-out')?.innerText || ''), null, { timeout: 10000 });
  await page.click('#save');
  await page.waitForSelector('#rules-msg .msg.ok', { timeout: 10000 });
  await shot(page, 'p2_marked');

  // After: Review & change lists the personal Safe with its note
  await page.click('nav button[data-page="review-safes"]');
  await page.waitForSelector('#safes-table');
  const safes = await page.innerText('#safes-table');
  if (!safes.includes('P-jane.smith')) throw new Error('personal Safe not in the Safes list: ' + safes);
  if (/PRS-FLD-JANE/.test(safes)) throw new Error('the abbreviated Safe is still there');
  await shot(page, 'p3_review');
  // Each person is a member of their own Safe; the folder report's Owner shows in the notes
  await page.click('.tabs [data-tab="members"]');
  await page.waitForFunction(() => /jane\.smith@corp\.example\.com/.test(document.querySelector('#main').innerText), null, { timeout: 10000 });
  const members = await page.innerText('#main');
  for (const t of ['jane.smith@corp.example.com', 'Nobody Known'])
    if (!members.includes(t)) throw new Error('personal Safe owner missing: ' + t);
  await shot(page, 'p4_owners');

  if (errors.length) throw new Error('page errors: ' + errors.join('; '));
  await browser.close();
  console.log('PASS');
})().catch(e => { console.error('FAIL', e); process.exit(1); });
