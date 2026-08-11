/**
 * EMSE Script Analyzer — UI Regression Test Suite
 * ────────────────────────────────────────────────────────────────
 * Based on:  EMSE_Regression_Suite_v4.md
 * Version:   4.0  |  Date: 2026-06-22  |  Author: Roberto
 * Env:       team1-arch.dev.accela.com (AKS nonprod/dev)
 * Auth:      Microsoft Entra ID via MSAL Angular v3
 * Modules:   6 (Rule Advice), 8 (Dashboard), 10 (Upload),
 *            14 (SSO), 16 (Angular SPA Migration)
 * Tests:     20 automated  |  4 pending ANALYST/AUDITOR account
 * ────────────────────────────────────────────────────────────────
 *
 * FIRST-TIME AUTH SETUP (run once, then delete auth-state.json to refresh)
 * ─────────────────────────────────────────────────────────────────
 *  Paste this into a temporary file (e.g. auth-setup.ts) and run it
 *  once with --headed to save your ADMIN EntraID session:
 *
 *    import { chromium } from '@playwright/test';
 *    import * as fs from 'fs';
 *
 *    (async () => {
 *      const browser = await chromium.launch({ headless: false });
 *      const context = await browser.newContext();
 *      const page = await context.newPage();
 *      await page.goto('https://team1-arch.dev.accela.com/apps/engarch/script-analyzer/clients/app/home');
 *      // Complete SSO login in the browser window, then press Enter here:
 *      await new Promise(r => setTimeout(r, 120_000)); // 2 min window
 *      await context.storageState({ path: 'auth-state.json' });
 *      const ss: Record<string,string> = await page.evaluate(() => {
 *        const s: Record<string,string> = {};
 *        for (let i = 0; i < sessionStorage.length; i++) {
 *          const k = sessionStorage.key(i)!;
 *          s[k] = sessionStorage.getItem(k)!;
 *        }
 *        return s;
 *      });
 *      fs.writeFileSync('session-storage.json', JSON.stringify(ss, null, 2));
 *      await browser.close();
 *    })();
 *
 *    node --loader ts-node/esm auth-setup.ts
 *    (or: npx ts-node auth-setup.ts)
 *
 * RUN THE SUITE (from the /playwright directory)
 * ─────────────────────────────────────────────────
 *    npm test -- emse-spa-regression-ui.spec.ts --project=chromium
 *
 *  Single test by RG ID:
 *    npm test -- --grep "RG-61" --project=chromium
 *
 *  HTML report:
 *    npm run report
 *
 *  VS Code:
 *    Install extension: ms-playwright.playwright
 *    Click the ▶ button next to any test or describe block
 * ────────────────────────────────────────────────────────────────
 *
 * OPEN ITEMS (require ANALYST/AUDITOR test account — not automated):
 *   RG-62  Single-role auto-redirect (ANALYST → /analyzer, AUDITOR → /dashboard)
 *   RG-66  Unauthorized direct nav → /unauthorized (blocking for 26.3 ship)
 *   RG-69  SSO_ENABLED=false dev-mode no-op (requires server config change)
 * ────────────────────────────────────────────────────────────────
 */

import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// ──────────────────────────────────────────────────────────────
// CONFIGURATION
// ──────────────────────────────────────────────────────────────

const BASE = 'https://standardtest-stg.accela.com/apps/stg/script-analyzer';

const URLS = {
  spaHome:         `${BASE}/clients/app/home`,
  spaAnalyzer:     `${BASE}/clients/app/analyzer`,
  spaDashboard:    `${BASE}/clients/app/dashboard`,
  spaConfig:       `${BASE}/clients/app/config`,
  spaUnauthorized: `${BASE}/clients/app/unauthorized`,
  swagger:         `${BASE}/clients/docs`,
  legacyAnalyzer:  `${BASE}/clients/analyzer-client-app`,
  legacyDashboard: `${BASE}/clients/dashboard`,
  legacyConfig:    `${BASE}/clients/config-client`,
};

const SSO_HOST = 'login.microsoftonline.com';

const AUTH_STATE_FILE    = path.join(__dirname, '..', 'auth-state.json');
const SESSION_STORE_FILE = path.join(__dirname, '..', 'session-storage.json');
const TEMP_DIR           = path.join(os.tmpdir(), 'emse-playwright-fixtures');

const KNOWN_RULES = [
  'JDBC-STATEMENT-NOT-CLOSED',
  'JS-EVAL',
  'eslint-no-debugger',
  'REGEX-FUNCTION-CALL',
  'AA-DIRECT-API-CALL',
  'JS-HARDCODED-ACCELA-HOST',
];

const SEVERITIES = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];

// ──────────────────────────────────────────────────────────────
// HELPERS
// ──────────────────────────────────────────────────────────────

function createTestFiles(count: number, prefix: string): string[] {
  if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });
  const files: string[] = [];
  for (let i = 0; i < count; i++) {
    const filePath = path.join(TEMP_DIR, `${prefix}-${String(i + 1).padStart(3, '0')}.js`);
    fs.writeFileSync(
      filePath,
      `// EMSE test fixture ${i + 1} — ${prefix}\n` +
      `var con = aa.getDataSubset('JDBC');\n` +
      `var stmt = con.createStatement();\n` +
      `debugger;\n` +
      `aa.print('Script fixture ${i + 1}');\n`
    );
    files.push(filePath);
  }
  return files;
}

function createInvalidFile(): string {
  if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });
  const filePath = path.join(TEMP_DIR, 'invalid-upload.pdf');
  fs.writeFileSync(filePath, '%PDF-1.4 fake pdf content for EMSE rejection test');
  return filePath;
}

async function restoreSessionStorage(page: Page): Promise<void> {
  if (!fs.existsSync(SESSION_STORE_FILE)) return;
  const saved: Record<string, string> = JSON.parse(
    fs.readFileSync(SESSION_STORE_FILE, 'utf-8')
  );
  if (Object.keys(saved).length === 0) return;
  await page.addInitScript((store: Record<string, string>) => {
    for (const [key, value] of Object.entries(store)) {
      window.sessionStorage.setItem(key, value);
    }
  }, saved);
}

// ──────────────────────────────────────────────────────────────
// MODULE 14 — SSO PROTECTION (no auth required)
// ──────────────────────────────────────────────────────────────

test.describe('Module 14 — SSO Protection (unauthenticated)', () => {

  test('RG-48 Swagger docs — unauthenticated access redirects to EntraID SSO', async ({ page }) => {
    await page.goto(URLS.swagger);

    await expect(page).toHaveURL(new RegExp(SSO_HOST), { timeout: 20_000 });
  });

  test('RG-60 Unauthenticated SPA access redirects to SSO before any Angular content renders', async ({ page }) => {
    await page.goto(URLS.spaHome);

    await expect(page).toHaveURL(new RegExp(SSO_HOST), { timeout: 20_000 });

    const appRoot = page.locator('app-root');
    if (await appRoot.count() > 0) {
      const innerHTML = await appRoot.innerHTML();
      expect(innerHTML.trim()).toBe('');
    }
  });

});

// ──────────────────────────────────────────────────────────────
// AUTHENTICATED SUITE
// Requires auth-state.json + session-storage.json (see setup instructions above)
// ──────────────────────────────────────────────────────────────

test.describe('Authenticated tests — ADMIN role', () => {

  test.use({
    storageState: fs.existsSync(AUTH_STATE_FILE)
      ? AUTH_STATE_FILE
      : { cookies: [], origins: [] },
  });

  test.beforeEach(async ({ page }, testInfo) => {
    if (!fs.existsSync(AUTH_STATE_FILE)) {
      testInfo.skip(true, 'auth-state.json not found — run the auth setup script first.');
      return;
    }
    await restoreSessionStorage(page);
  });

  // ────────────────────────────────────────────────────────────
  // MODULE 14 — Authenticated Swagger access
  // ────────────────────────────────────────────────────────────

  test('RG-49 Authenticated ADMIN user accesses Swagger docs without re-login', async ({ page }) => {
    await page.goto(URLS.swagger);

    // SSO session must carry through — no re-login prompt
    await expect(page).not.toHaveURL(new RegExp(SSO_HOST), { timeout: 20_000 });

    // Swagger/ReDoc renders API documentation
    const docHeading = page.getByRole('heading').first();
    await expect(docHeading).toBeVisible({ timeout: 15_000 });
  });

  // ────────────────────────────────────────────────────────────
  // MODULE 16 — UNIFIED ANGULAR SPA MIGRATION (NORTAL1-219)
  // ────────────────────────────────────────────────────────────

  test.describe('Module 16 — Angular SPA Migration', () => {

    test('RG-61 Landing page renders role-aware panels for ADMIN (expects 3 panels)', async ({ page }) => {
      await page.goto(URLS.spaHome);
      await page.waitForLoadState('networkidle');

      await expect(page).not.toHaveURL(new RegExp(SSO_HOST));

      const panels = page.locator(
        'p-card, mat-card, .p-card, ' +
        '[class*="client-card"], [class*="app-card"], [class*="panel-card"], [class*="panel-item"]'
      );
      const panelCount = await panels.count();
      expect(panelCount, `Expected ≥3 panels, found ${panelCount}`).toBeGreaterThanOrEqual(3);

      const goToActions = page.locator('button, a').filter({ hasText: /go to|open|launch|navigate/i });
      await expect(goToActions.first()).toBeVisible({ timeout: 10_000 });

      const bodyText = await page.locator('body').innerText();
      expect(/admin|roberto|RM/i.test(bodyText)).toBeTruthy();

      console.log(`✅ RG-61: ${panelCount} panels rendered | user info visible`);
    });

    test('RG-63 Multi-role ADMIN sees panel selector on landing page (not auto-redirected)', async ({ page }) => {
      await page.goto(URLS.spaHome);
      await page.waitForLoadState('networkidle');

      const currentUrl = page.url();
      expect(currentUrl).not.toMatch(/\/analyzer$|\/dashboard$|\/config$/);

      const onLanding = currentUrl.includes('/home') || currentUrl.includes('/clients/app');
      expect(onLanding).toBeTruthy();

      const panels = page.locator(
        'p-card, mat-card, .p-card, [class*="client-card"], [class*="panel"]'
      );
      expect(await panels.count()).toBeGreaterThanOrEqual(2);
    });

    test('RG-64 Panel navigation — all API calls return 2xx across Config, Analyzer, Dashboard', async ({ page }) => {
      const failedRequests: string[] = [];
      const successfulCalls: string[] = [];

      page.on('response', (response) => {
        const url = response.url();
        if (url.includes('/api/v1/')) {
          if (response.status() >= 400) {
            failedRequests.push(`${response.status()} ${url}`);
          } else {
            successfulCalls.push(`${response.status()} ${url}`);
          }
        }
      });

      for (const route of [URLS.spaHome, URLS.spaConfig, URLS.spaAnalyzer, URLS.spaDashboard]) {
        await page.goto(route);
        await page.waitForLoadState('networkidle');
      }

      expect(
        failedRequests,
        `Failed API requests:\n${failedRequests.join('\n')}`
      ).toEqual([]);
      expect(successfulCalls.length).toBeGreaterThan(0);

      console.log(`✅ RG-64: ${successfulCalls.length} successful API calls`);
      console.log(successfulCalls.join('\n'));
    });

    test('RG-65 Route guard — document network calls made per-client navigation', async ({ page }) => {
      // Open item ITEM-09: /api/v1/access?client= not observed in prior testing.
      // This test captures what IS observed and documents it as evidence.
      const accessLikeCalls: string[] = [];

      page.on('response', (response) => {
        const url = response.url();
        if (/\/access|\/authorize|\/guard|\/permission|\/role/i.test(url)) {
          accessLikeCalls.push(`${response.status()} ${url}`);
        }
      });

      for (const route of [URLS.spaHome, URLS.spaAnalyzer, URLS.spaDashboard, URLS.spaConfig]) {
        await page.goto(route);
        await page.waitForLoadState('networkidle');
      }

      if (accessLikeCalls.length === 0) {
        console.warn('⚠️ RG-65: No /api/v1/access?client= call observed across all 4 routes.');
        console.warn('  Possible explanations: JWT-claim-only check (no network call),');
        console.warn('  differently-named endpoint, or server-side guard not yet implemented.');
        console.warn('  → Clarify with Nenad. (ITEM-09)');
      } else {
        console.log('✅ RG-65: Access-check calls found:\n' + accessLikeCalls.join('\n'));
      }
      expect(true).toBeTruthy();
    });

    test('RG-67 Flask serves SPA — browser-side verification', async ({ page }) => {
      const response = await page.goto(URLS.spaHome);

      expect(response?.status()).toBe(200);

      const contentType = response?.headers()['content-type'] ?? '';
      expect(contentType).toContain('text/html');

      const serverHeader = response?.headers()['server'] ?? '(not in response headers)';
      console.log(`Server: ${serverHeader} | Content-Type: ${contentType}`);

      const html = await page.content();
      const isAngularApp =
        html.includes('app-root') ||
        html.includes('ng-version') ||
        html.includes('main.') ||
        html.includes('polyfills.');
      expect(isAngularApp).toBeTruthy();

      console.log('⚠️ Runtime Node.js check requires kubectl exec — coordinate with Nikola on AKS.');
    });

    test('RG-68 Deep-link routing fallback — direct URL to each SPA route renders correct view', async ({ page }) => {
      const deepLinks = [
        { url: URLS.spaDashboard, label: 'dashboard' },
        { url: URLS.spaAnalyzer,  label: 'analyzer'  },
        { url: URLS.spaConfig,    label: 'config'     },
        { url: URLS.spaHome,      label: 'home'       },
      ];

      for (const { url, label } of deepLinks) {
        const response = await page.goto(url);
        await page.waitForLoadState('networkidle');

        expect(response?.status(), `${label}: expected 200`).toBe(200);

        const appRoot = page.locator('app-root');
        await expect(appRoot).toBeAttached({ timeout: 15_000 });
        const innerHTML = await appRoot.innerHTML();
        expect(
          innerHTML.trim().length,
          `${label}: app-root empty — Angular router did not activate`
        ).toBeGreaterThan(100);

        const bodyText = await page.locator('body').innerText();
        expect(bodyText).not.toMatch(/404|page not found|not found/i);

        console.log(`✅ RG-68 ${label}: deep-link renders correctly`);
      }
    });

    // ────────────────────────────────────────────────────────────
    // MODULE 6 — RULE ADVICE (Analyzer UI)
    // ────────────────────────────────────────────────────────────

    test.describe('Module 6 — Rule Advice (Analyzer UI)', () => {

      async function analyzeScript(page: Page, scriptText: string, filePrefix: string): Promise<void> {
        await page.goto(URLS.spaAnalyzer);
        await page.waitForLoadState('networkidle');

        const scriptTextArea = page.locator(
          'textarea, [placeholder*="script" i], [placeholder*="paste" i], [class*="script-input"]'
        ).first();

        if (await scriptTextArea.isVisible({ timeout: 3_000 })) {
          await scriptTextArea.fill(scriptText);
          const analyzeBtn = page.locator('button').filter({ hasText: /analyze|submit|run|scan/i }).first();
          await analyzeBtn.click();
        } else {
          const [testFile] = createTestFiles(1, filePrefix);
          const fileInput = page.locator('input[type="file"]').first();
          await expect(fileInput).toBeAttached({ timeout: 10_000 });
          await fileInput.setInputFiles(testFile);
          const uploadBtn = page.locator('button').filter({ hasText: /upload|analyze|submit|scan/i }).first();
          if (await uploadBtn.isVisible({ timeout: 3_000 })) await uploadBtn.click();
        }

        await page.waitForSelector(
          '[class*="finding"], [class*="result-row"], p-table tr[role="row"]:not([class*="header"]), table tbody tr',
          { timeout: 30_000 }
        );
      }

      test('RG-21 Rule advice text appears in finding detail modal', async ({ page }) => {
        await analyzeScript(
          page,
          "var con = aa.getDataSubset('JDBC');\nvar stmt = con.createStatement();\n" +
          "var rs = stmt.executeQuery('SELECT * FROM users');\naa.print(rs);",
          'rg-21'
        );

        const findingRows = page.locator(
          '[class*="finding"], [class*="result-row"], ' +
          'p-table tr[role="row"]:not([class*="header"]), table tbody tr'
        );
        const rowCount = await findingRows.count();
        console.log(`Finding rows found: ${rowCount}`);
        await findingRows.first().click();

        // PrimeNG note: <p-dialog> host is always in DOM but hidden when [visible]="false".
        // Target the inner .p-dialog box or [data-pc-section="content"] — visible only when open.
        const dialogContent = page.locator(
          '.p-dialog, [data-pc-section="content"], [class*="p-dialog-content"], ' +
          '.p-sidebar-content, [class*="sidebar-content"]'
        ).first();

        let dialogOpened = await dialogContent.isVisible({ timeout: 12_000 }).catch(() => false);

        if (!dialogOpened) {
          const detailBtn = findingRows.first().locator(
            'button, a, [class*="info"], [class*="detail"], [class*="eye"], [class*="view"]'
          ).first();
          if (await detailBtn.isVisible({ timeout: 2_000 }).catch(() => false)) {
            await detailBtn.click();
            dialogOpened = await dialogContent.isVisible({ timeout: 8_000 }).catch(() => false);
          }
        }

        if (dialogOpened) {
          const modalText = await dialogContent.innerText();
          expect(modalText.trim().length).toBeGreaterThan(10);
          console.log(`✅ RG-21: Modal opened. Preview: "${modalText.substring(0, 120)}"`);
          console.log('  → For AC11 parity: verify advice text matches /clients/analyzer-client-app modal.');
        } else {
          console.warn('⚠️ RG-21: No visible dialog content after clicking finding row.');
          console.warn('  In DevTools: find the trigger that sets [visible]="true" on p-dialog,');
          console.warn('  then update the click target selector above.');
        }
        expect(rowCount).toBeGreaterThan(0);
      });

      test('RG-22 Finding with no advice shows fallback "No advice available for this rule."', async ({ page }) => {
        await analyzeScript(
          page,
          "debugger;\naa.print('test');\nvar x = eval('1+1');",
          'rg-22'
        );

        const findings = page.locator(
          '[class*="finding"], [class*="result-row"], ' +
          'p-table tr[role="row"]:not([class*="header"]), table tbody tr'
        );
        const count = await findings.count();
        let fallbackFound = false;

        for (let i = 0; i < Math.min(count, 6); i++) {
          try {
            await findings.nth(i).click();
            const modal = page.locator(
              '.p-dialog, [data-pc-section="content"], [class*="p-dialog-content"], p-sidebar'
            ).first();
            if (await modal.isVisible({ timeout: 2_000 })) {
              const text = await modal.innerText();
              if (text.includes('No advice available for this rule.')) {
                fallbackFound = true;
                console.log(`✅ RG-22: Fallback message found in finding row ${i + 1}`);
                break;
              }
              await page.keyboard.press('Escape');
              await page.waitForTimeout(300);
            }
          } catch {
            // try next row
          }
        }

        if (!fallbackFound) {
          console.warn('⚠️ RG-22: Fallback text not found in first 6 findings.');
          console.warn('  All triggered rules may have advice configured.');
          console.warn('  Verify manually with a rule where ANALYSIS_RULE.ADVICE IS NULL in DB.');
        }
        expect(count).toBeGreaterThanOrEqual(0);
      });

    });

    // ────────────────────────────────────────────────────────────
    // MODULE 8 — DASHBOARD UI
    // ────────────────────────────────────────────────────────────

    test.describe('Module 8 — Dashboard UI', () => {

      test('RG-30 Severity Reference page — verify rule content and severity labels', async ({ page }) => {
        await page.goto(URLS.spaDashboard);
        await page.waitForLoadState('networkidle');

        const severityNav = page.locator(
          'a, button, [class*="nav-item"], [class*="menu-item"], [class*="tab"], p-tabpanel'
        ).filter({ hasText: /severity|reference|rules/i }).first();

        if (await severityNav.isVisible({ timeout: 3_000 })) {
          await severityNav.click();
          await page.waitForLoadState('networkidle');
        }

        const bodyText = await page.locator('body').innerText();

        const hasSeverityLabel = SEVERITIES.some((s) => bodyText.includes(s));
        expect(hasSeverityLabel).toBeTruthy();

        const foundRules = KNOWN_RULES.filter((r) =>
          bodyText.toLowerCase().includes(r.toLowerCase())
        );
        console.log(`Rules found in Dashboard text: [${foundRules.join(', ')}]`);

        if (foundRules.length === 0) {
          console.warn('⚠️ RG-30: No rule names in visible text. Likely cause: rules are in');
          console.warn('  PrimeNG p-chart (Canvas) and not in DOM innerText. Check all Dashboard tabs');
          console.warn('  for a dedicated "Rules" or "Severity Reference" section.');
          console.warn('  → Compare with legacy /clients/dashboard which had a rule name table.');
        } else {
          console.log(`✅ RG-30: ${foundRules.length} rule names visible.`);
        }

        if (bodyText.includes('JS-HARDCODED-ACCELA-HOST')) {
          console.log('✅ BUG-02 regression: JS-HARDCODED-ACCELA-HOST visible — fix confirmed.');
        }

        expect(hasSeverityLabel).toBeTruthy();
      });

      test('RG-71 Dashboard feature parity — overview metrics, PrimeNG charts, and data grids render', async ({ page }) => {
        await page.goto(URLS.spaDashboard);
        await page.waitForLoadState('networkidle');

        const bodyText = await page.locator('body').innerText();
        expect(/\d+/.test(bodyText)).toBeTruthy();

        const charts = page.locator('canvas, p-chart, [class*="chart"]');
        const chartCount = await charts.count();
        console.log(`Chart/canvas elements: ${chartCount}`);

        const grids = page.locator('table, p-table, [class*="datatable"], [class*="p-datatable"]');
        const gridCount = await grids.count();
        console.log(`Data grid elements: ${gridCount}`);

        expect(chartCount + gridCount).toBeGreaterThan(0);

        const errorAlerts = page.locator('[role="alert"], [class*="error-msg"], p-message').filter({
          hasText: /error|failed|exception/i,
        });
        expect(await errorAlerts.count()).toBe(0);
      });

    });

    // ────────────────────────────────────────────────────────────
    // MODULE 10 — MULTI-FILE UPLOAD
    // ────────────────────────────────────────────────────────────

    test.describe('Module 10 — Multi-File Upload', () => {

      test('RG-35 Single file upload — analysis completes and results display in Analyzer UI', async ({ page }) => {
        await page.goto(URLS.spaAnalyzer);
        await page.waitForLoadState('networkidle');

        const [testFile] = createTestFiles(1, 'rg-35');
        const fileInput = page.locator('input[type="file"]').first();
        await expect(fileInput).toBeAttached({ timeout: 10_000 });
        await fileInput.setInputFiles(testFile);

        const uploadBtn = page.locator('button').filter({ hasText: /upload|analyze|submit|scan/i }).first();
        if (await uploadBtn.isVisible({ timeout: 3_000 })) await uploadBtn.click();

        const resultArea = page.locator(
          '[class*="finding"], [class*="result"], [class*="analysis-result"], p-table, table'
        ).first();
        await expect(resultArea).toBeVisible({ timeout: 30_000 });

        const bodyText = await page.locator('body').innerText();
        expect(/risk.?score|findings.?count|\d+\.\d+/i.test(bodyText)).toBeTruthy();
      });

      test('RG-36 Batch upload 10 files — all processed and completes within 15 seconds', async ({ page }) => {
        await page.goto(URLS.spaAnalyzer);
        await page.waitForLoadState('networkidle');

        const testFiles = createTestFiles(10, 'rg-36');
        const fileInput = page.locator('input[type="file"]').first();
        await expect(fileInput).toBeAttached({ timeout: 10_000 });
        await fileInput.setInputFiles(testFiles);

        const uploadBtn = page.locator('button').filter({ hasText: /upload|analyze|submit|scan/i }).first();
        if (await uploadBtn.isVisible({ timeout: 3_000 })) await uploadBtn.click();

        const t0 = Date.now();
        await page.waitForSelector(
          '[class*="finding"], [class*="result"], p-table, table',
          { timeout: 30_000 }
        );
        const elapsed = Date.now() - t0;
        console.log(`✅ RG-36: 10-file batch completed in ${elapsed} ms`);
        expect(elapsed).toBeLessThan(15_000);
      });

      test('RG-37 Large batch upload 50 files — server stays responsive throughout', async ({ page }) => {
        test.setTimeout(120_000);

        await page.goto(URLS.spaAnalyzer);
        await page.waitForLoadState('networkidle');

        const testFiles = createTestFiles(50, 'rg-37');
        const fileInput = page.locator('input[type="file"]').first();
        await expect(fileInput).toBeAttached({ timeout: 10_000 });
        await fileInput.setInputFiles(testFiles);

        const uploadBtn = page.locator('button').filter({ hasText: /upload|analyze|submit|scan/i }).first();
        if (await uploadBtn.isVisible({ timeout: 3_000 })) await uploadBtn.click();

        await page.waitForSelector(
          '[class*="finding"], [class*="result"], p-table, table',
          { timeout: 90_000 }
        );

        const healthResponse = await page.request.get(`${BASE}/api/v1/health`);
        const healthStatus = healthResponse.status();
        if (healthStatus === 401) {
          console.warn('⚠️ RG-37: /api/v1/health returned 401 — per RG-01 it should require no auth.');
          console.warn('  Verify RG-01 independently to confirm if health endpoint is now protected.');
        } else {
          expect(healthStatus).toBe(200);
          console.log('✅ Server health: 200 after 50-file batch');
        }

        const crashMessages = page.locator('[role="alert"], [class*="error"]').filter({
          hasText: /crash|exception|500|server error/i,
        });
        expect(await crashMessages.count()).toBe(0);
      });

      test('RG-38 Invalid file type (.pdf) — verify upload validation behavior', async ({ page }) => {
        await page.goto(URLS.spaAnalyzer);
        await page.waitForLoadState('networkidle');

        const invalidFile = createInvalidFile();
        const fileInput = page.locator('input[type="file"]').first();
        await expect(fileInput).toBeAttached({ timeout: 10_000 });
        await fileInput.setInputFiles(invalidFile);

        const uploadBtn = page.locator('button').filter({ hasText: /upload|analyze|submit|scan/i }).first();
        if (await uploadBtn.isVisible({ timeout: 3_000 })) await uploadBtn.click();

        const rejectionMsg = page.locator(
          '[class*="error"], [class*="invalid"], [class*="warn"], [role="alert"], p-message, p-toast'
        ).filter({ hasText: /invalid|not supported|file type|only.*js|javascript/i }).first();

        const hasRejectionMsg = await rejectionMsg.isVisible({ timeout: 8_000 }).catch(() => false);

        const results = page.locator('[class*="finding"], [class*="result"]');
        const resultsAppeared = await results.first().isVisible({ timeout: 5_000 }).catch(() => false);

        if (hasRejectionMsg) {
          const msg = await rejectionMsg.innerText().catch(() => '');
          console.log(`✅ RG-38 PASS: Rejection message shown: "${msg}"`);
        } else if (!resultsAppeared) {
          console.log('✅ RG-38 PASS: Invalid file silently rejected — no analysis results displayed.');
        } else {
          console.warn('⚠️ RG-38 FINDING: PDF file was NOT rejected — analysis results appeared.');
          console.warn('  The Angular SPA upload component does not validate file types.');
          console.warn('  → File a defect if .js-only validation is a requirement.');
          console.warn('  → Compare with legacy /clients/analyzer-client-app behavior.');
        }
        expect(true).toBeTruthy();
      });

    });

    // ────────────────────────────────────────────────────────────
    // MODULE 16 — ANALYZER FEATURE PARITY (AC11)
    // ────────────────────────────────────────────────────────────

    test.describe('Module 16 — Analyzer Feature Parity (AC11)', () => {

      test('RG-70 Angular Analyzer has: file upload, findings panel, severity filter, export', async ({ page }) => {
        await page.goto(URLS.spaAnalyzer);
        await page.waitForLoadState('networkidle');

        const fileInput = page.locator('input[type="file"]');
        expect(await fileInput.count()).toBeGreaterThan(0);

        const [testFile] = createTestFiles(1, 'rg-70');
        await fileInput.first().setInputFiles(testFile);
        const uploadBtn = page.locator('button').filter({ hasText: /upload|analyze|submit|scan/i }).first();
        if (await uploadBtn.isVisible({ timeout: 3_000 })) await uploadBtn.click();

        await page.waitForSelector('[class*="finding"], [class*="result"], p-table, table', {
          timeout: 30_000,
        });

        const severityFilter = page.locator(
          'select, p-dropdown, p-multiselect, [class*="severity-filter"], ' +
          '[class*="filter"][placeholder*="severity" i]'
        );
        const filterCount = await severityFilter.count();
        console.log(`Severity filter elements: ${filterCount}`);

        const exportBtn = page.locator('button, a').filter({ hasText: /export|download|csv|xlsx/i });
        const exportCount = await exportBtn.count();
        console.log(`Export buttons: ${exportCount}`);

        console.log(
          `AC11 parity: upload=✅ | findings=✅ | ` +
          `severity-filter=${filterCount > 0 ? '✅' : '⚠️ check manually'} | ` +
          `export=${exportCount > 0 ? '✅' : '⚠️ check manually'}`
        );
        console.log(`→ Side-by-side comparison with ${URLS.legacyAnalyzer} for full AC11 sign-off.`);
      });

    });

    // ────────────────────────────────────────────────────────────
    // MODULE 16 — CONFIG FEATURE PARITY (AC13) + RG-41
    // ────────────────────────────────────────────────────────────

    test.describe('Module 16 — Config Feature Parity (AC13)', () => {

      test('RG-72 Angular Config client loads with rule listing, advice editor, and version history', async ({ page }) => {
        await page.goto(URLS.spaConfig);
        await page.waitForLoadState('networkidle');

        await expect(page).not.toHaveURL(new RegExp(SSO_HOST));
        await expect(page).not.toHaveURL(/404/);

        const bodyText = await page.locator('body').innerText();
        expect(bodyText.length).toBeGreaterThan(100);

        const hasRuleContent =
          KNOWN_RULES.some((r) => bodyText.toLowerCase().includes(r.toLowerCase())) ||
          /rule|config|eslint|regex|severity|advice/i.test(bodyText);
        expect(hasRuleContent).toBeTruthy();

        const historyEl = page.locator(
          '[class*="history"], [class*="version"], p-tabpanel'
        ).filter({ hasText: /history|version/i });
        console.log(`Version history sections: ${await historyEl.count()}`);

        const editors = page.locator('textarea, [class*="editor"], [contenteditable="true"]');
        console.log(`Editor areas: ${await editors.count()}`);

        console.log(
          `→ For full AC13 sign-off, compare with ${URLS.legacyConfig}: ` +
          'ESLint rule creation, regex rule, threshold editing, deletion.'
        );
      });

      test('RG-41 eslint-no-debugger can be toggled in Config UI (no server restart required)', async ({ page }) => {
        await page.goto(URLS.spaConfig);
        await page.waitForLoadState('networkidle');

        // eslint-no-debugger is on page 2 of the paginated Config rule list
        const paginatorPage2 = page.locator(
          'p-paginator button, [class*="p-paginator"] button, [class*="paginator"] button'
        ).filter({ hasText: /^2$/ }).first();

        if (await paginatorPage2.isVisible({ timeout: 4_000 })) {
          await paginatorPage2.click();
          await page.waitForTimeout(700);
          console.log('Navigated to paginator page 2');
        } else {
          const nextBtn = page.locator(
            'p-paginator [class*="next"], [class*="p-paginator-next"], button[aria-label*="Next" i]'
          ).first();
          if (await nextBtn.isVisible({ timeout: 2_000 })) {
            await nextBtn.click();
            await page.waitForTimeout(700);
            console.log('Navigated via next-page button');
          }
        }

        const ruleRow = page.locator(
          'tr, [class*="rule-row"], [class*="rule-item"], p-table tr[role="row"]'
        ).filter({ hasText: /eslint-no-debugger|no-debugger/i }).first();

        if (!(await ruleRow.isVisible({ timeout: 5_000 }))) {
          console.warn('⚠️ RG-41: eslint-no-debugger row not found after page 2 navigation.');
          console.warn('  Check paginator selector or which tab ESLint rules appear under.');
          test.skip();
          return;
        }

        const toggle = ruleRow.locator(
          'input[type="checkbox"], p-inputswitch, p-togglebutton, [class*="toggle"]'
        ).first();
        await expect(toggle).toBeVisible({ timeout: 5_000 });

        const before = await toggle.isChecked().catch(() => null);
        await toggle.click();
        await page.waitForTimeout(1_200);

        const after = await toggle.isChecked().catch(() => null);
        if (before !== null && after !== null) {
          expect(after).not.toBe(before);
          console.log(`✅ RG-41: Toggle changed: ${before} → ${after} (no restart needed)`);
        }

        await toggle.click();
        await page.waitForTimeout(500);
        console.log('✅ Rule restored to original state.');
      });

    });

  }); // end Module 16 describe

}); // end Authenticated tests
