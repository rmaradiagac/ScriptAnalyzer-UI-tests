/**
 * EMSE Auth Setup — run once to save your Microsoft EntraID session.
 *
 * Usage (from the /playwright directory):
 *   node auth-setup.js
 *
 * What it does:
 *   1. Opens a headed browser window
 *   2. Navigates to the EMSE SPA home (triggers SSO redirect)
 *   3. You complete the Microsoft login in the browser — you have 2 minutes
 *   4. Saves cookies + localStorage → auth-state.json
 *   5. Saves sessionStorage (MSAL tokens) → session-storage.json
 *
 * Re-run whenever the suite starts redirecting to login.microsoftonline.com.
 */

const { chromium } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

const SPA_URL = 'https://team1-arch.dev.accela.com/apps/engarch/script-analyzer/clients/app/home';
const AUTH_STATE = path.join(__dirname, 'auth-state.json');
const SESSION_STORE = path.join(__dirname, 'session-storage.json');
const LOGIN_TIMEOUT_MS = 120_000; // 2 minutes

(async () => {
  console.log('Launching browser...');
  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext();
  const page = await context.newPage();

  await page.goto(SPA_URL);
  console.log('\n➡️  Complete the Microsoft SSO login in the browser window.');
  console.log(`   You have ${LOGIN_TIMEOUT_MS / 1000} seconds.\n`);

  await new Promise((r) => setTimeout(r, LOGIN_TIMEOUT_MS));

  // Save cookies + localStorage (standard Playwright storage state)
  await context.storageState({ path: AUTH_STATE });
  console.log(`✅ auth-state.json saved → ${AUTH_STATE}`);

  // Save sessionStorage separately — MSAL v3 stores tokens here and
  // Playwright's storageState() does not capture sessionStorage.
  const sessionData = await page.evaluate(() => {
    const store = {};
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      store[key] = sessionStorage.getItem(key);
    }
    return store;
  });

  const keyCount = Object.keys(sessionData).length;
  fs.writeFileSync(SESSION_STORE, JSON.stringify(sessionData, null, 2));
  console.log(`✅ session-storage.json saved → ${SESSION_STORE} (${keyCount} MSAL keys)`);

  await browser.close();

  if (keyCount === 0) {
    console.warn('\n⚠️  session-storage.json has 0 keys — the login may not have completed in time.');
    console.warn('   Delete both JSON files and run auth-setup.js again.');
  } else {
    console.log('\n🎉 Auth setup complete. Run the suite now:');
    console.log('   npm test -- emse-spa-regression-ui.spec.ts --project=chromium');
  }
})();
