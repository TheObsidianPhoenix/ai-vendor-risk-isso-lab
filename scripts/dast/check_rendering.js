// Confirms stored script payloads are shown as text, never run (see docs/system-security/dast-local-zap.md).
// Usage: node scripts/dast/check_rendering.js "<cookie name=value from .dast/seed.json>" <vendor id with a payload in its name>
// Needs Playwright with Chromium.
const { chromium } = require('playwright');
(async () => {
  const [cookie] = process.argv.slice(2);
  const [name, value] = cookie.split('=');
  const browser = await chromium.launch();
  const ctx = await browser.newContext();
  await ctx.addCookies([{ name, value, domain: '127.0.0.1', path: '/' }]);
  const page = await ctx.newPage();
  let dialogs = 0, cspViolations = 0;
  page.on('dialog', async d => { dialogs++; await d.dismiss(); });
  page.on('console', m => { if (/Content Security Policy/i.test(m.text())) cspViolations++; });
  const results = {};
  for (const hash of ['#overview', '#vendors', '#vendor/' + process.argv[3]]) {
    await page.goto('http://127.0.0.1:8000/' + hash);
    await page.waitForTimeout(2500);
    results[hash] = await page.evaluate(() => document.body.innerText.includes('<script>alert(1);</script>'));
  }
  const scriptsInBody = await page.evaluate(() => document.body.querySelectorAll('script').length);
  const shown = results;
  console.log(JSON.stringify({ dialogs, cspViolations, scriptsInBody, payloadShownAsText: shown }));
  await browser.close();
})();
