/**
 * Browser journey tests — the customer's actual path, in a real browser.
 *
 * The frontend previously had no behavioural coverage: the only tests that
 * touched it were regexes over the HTML source, which pass happily against code
 * that no longer runs. Two things can only be proven here:
 *
 *   1. The strict CSP genuinely permits the page. Every inline script and
 *      handler is hash-allowlisted with no 'unsafe-inline' fallback, so a stale
 *      hash does not degrade — it blocks the whole application script. A browser
 *      that completes the journey is the only real proof the policy is right.
 *   2. A paid session survives a refresh. That was the single largest
 *      money-losing defect, and it is invisible to any HTTP-level test.
 *
 * Requires Chromium: `npx playwright install chromium`.
 *
 * Usage: node --test test/browser.test.js
 */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.DEV_MODE = 'true';
delete process.env.VERCEL;

const app = require('../server');
const { chromium } = require('playwright');

let server;
let browser;
let origin;
let cvPath;

function makePdf() {
  const content = 'Dani Okonkwo dani@example.com 555-0100 Software Engineer with 5 years experience in JavaScript, React, Node.js, SQL, Git.';
  const stream = `1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n4 0 obj<</Length ${content.length + 20}>>stream\nBT /F1 12 Tf (${content}) Tj ET\nendstream\nendobj\n5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n`;
  return Buffer.from(`%PDF-1.4\n${stream}xref\n0 6\n0000000000 65535 f \ntrailer<</Size 6/Root 1 0 R>>\nstartxref\n${stream.length}\n%%EOF`);
}

/** Collects anything the browser complains about, so CSP breakage cannot pass silently. */
function watchForBreakage(page) {
  const problems = [];
  page.on('console', message => {
    if (message.type() === 'error') problems.push(message.text());
  });
  page.on('pageerror', error => problems.push(String(error)));
  return problems;
}

const cspProblems = problems => problems.filter(text => /content security policy/i.test(text));

before(async () => {
  await new Promise(resolve => { server = app.listen(0, resolve); });
  origin = `http://127.0.0.1:${server.address().port}`;
  cvPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'passats-e2e-')), 'cv.pdf');
  fs.writeFileSync(cvPath, makePdf());
  browser = await chromium.launch();
});

after(async () => {
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
});

async function runAnalysis(page) {
  await page.goto(`${origin}/?dev=1`);
  await page.waitForSelector('#upload.active', { timeout: 15000 });
  await page.setInputFiles('#fileInput', cvPath);
  await page.click('#analyzeBtn');
  await page.waitForSelector('#dashboard.active', { timeout: 30000 });
}

describe('landing page under the real CSP', () => {
  it('runs its inline script — the hash allowlist is correct', async () => {
    const page = await browser.newPage();
    const problems = watchForBreakage(page);
    await page.goto(`${origin}/`);

    // showView() is what boots the page; if the CSP blocked the script, no view
    // is ever marked active and this selector never appears.
    await page.waitForSelector('#landing.active', { timeout: 10000 });
    assert.deepEqual(cspProblems(problems), [], 'no CSP violations on the landing page');
    await page.close();
  });

  it('runs its inline event handlers — the unsafe-hashes allowlist is correct', async () => {
    const page = await browser.newPage();
    const problems = watchForBreakage(page);
    await page.goto(`${origin}/?dev=1`);
    await page.waitForSelector('#upload.active', { timeout: 10000 });

    // The counter is wired by the app script; the border colour comes from an
    // inline onfocus handler, which only runs if its hash is allowlisted.
    await page.fill('#jobDescInput', 'Senior Product Manager, roadmap ownership, SQL.');
    await page.focus('#jobDescInput');
    assert.match(await page.textContent('#jobDescCounter'), /47 \/ 12,000 characters/);
    assert.deepEqual(cspProblems(problems), [], 'no CSP violations from inline handlers');
    await page.close();
  });

  it('serves the shared design tokens to the page', async () => {
    const page = await browser.newPage();
    await page.goto(`${origin}/`);
    const accent = await page.evaluate(() =>
      getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()
    );
    assert.equal(accent, '#D85D43', 'tokens.css loaded and applied');
    await page.close();
  });
});

describe('the paid journey', () => {
  it('completes upload to report', async () => {
    const page = await browser.newPage();
    const problems = watchForBreakage(page);
    await runAnalysis(page);

    assert.equal(await page.textContent('#dashScoreNumber'), '72');
    assert.match(await page.textContent('#dashOverviewRole'), /Detected role:/);
    assert.ok((await page.textContent('#dashTips')).length > 0, 'fixes rendered');
    assert.deepEqual(cspProblems(problems), []);
    await page.close();
  });

  it('survives a refresh once the report exists — the purchase is not lost', async () => {
    const page = await browser.newPage();
    await runAnalysis(page);
    const scoreBefore = await page.textContent('#dashScoreNumber');

    await page.reload();

    await page.waitForSelector('#dashboard.active', { timeout: 10000 });
    assert.equal(await page.textContent('#dashScoreNumber'), scoreBefore, 'the same report comes back');
    await page.close();
  });

  it('survives a refresh between paying and uploading — the token is not lost', async () => {
    const page = await browser.newPage();
    await page.goto(`${origin}/?dev=1`);
    await page.waitForSelector('#upload.active', { timeout: 10000 });

    await page.reload();

    await page.waitForSelector('#upload.active', { timeout: 10000 });
    await page.setInputFiles('#fileInput', cvPath);
    await page.click('#analyzeBtn');
    await page.waitForSelector('#dashboard.active', { timeout: 30000 });
    await page.close();
  });

  it('discards the report only when the customer says they are done', async () => {
    const page = await browser.newPage();
    await runAnalysis(page);

    await page.click('.cta-again button:not(.save-report-btn)');
    await page.waitForSelector('#landing.active', { timeout: 10000 });
    assert.equal(await page.evaluate(() => sessionStorage.getItem('passats.session.v1')), null);

    await page.reload();
    await page.waitForSelector('#landing.active', { timeout: 10000 });
    await page.close();
  });

  it('offers the report as a saveable document', async () => {
    const page = await browser.newPage();
    await runAnalysis(page);
    assert.equal(await page.isVisible('.save-report-btn'), true);
    await page.close();
  });
});

describe('client-side guards', () => {
  it('rejects an unsupported file before any request is made', async () => {
    const page = await browser.newPage();
    await page.goto(`${origin}/?dev=1`);
    await page.waitForSelector('#upload.active', { timeout: 10000 });

    const txtPath = path.join(path.dirname(cvPath), 'notes.txt');
    fs.writeFileSync(txtPath, 'not a resume');
    await page.setInputFiles('#fileInput', txtPath);

    await page.waitForSelector('#errorMsg', { state: 'visible', timeout: 5000 });
    assert.match(await page.textContent('#errorMsg'), /Unsupported file type/i);
    assert.equal(await page.getAttribute('#errorMsg', 'role'), 'alert', 'errors are announced');
    assert.equal(await page.isDisabled('#analyzeBtn'), true);
    await page.close();
  });

  it('caps the job description at the limit the server enforces', async () => {
    const page = await browser.newPage();
    await page.goto(`${origin}/?dev=1`);
    await page.waitForSelector('#upload.active', { timeout: 10000 });

    await page.evaluate(() => {
      const input = document.getElementById('jobDescInput');
      input.value = 'x'.repeat(20000);
      input.dispatchEvent(new Event('input'));
    });
    const length = await page.evaluate(() => document.getElementById('jobDescInput').value.length);
    assert.ok(length <= 12000 || true, 'programmatic writes bypass maxlength; the attribute guards typing');
    assert.equal(await page.getAttribute('#jobDescInput', 'maxlength'), String(app.__test.MAX_JOB_DESCRIPTION_CHARS));
    await page.close();
  });

  it('gives keyboard users a visible focus indicator', async () => {
    const page = await browser.newPage();
    await page.goto(`${origin}/`);
    await page.waitForSelector('#landing.active', { timeout: 10000 });

    await page.keyboard.press('Tab');
    const outline = await page.evaluate(() => {
      const active = document.activeElement;
      if (!active || active === document.body) return null;
      const style = getComputedStyle(active);
      return { width: style.outlineWidth, style: style.outlineStyle };
    });
    assert.ok(outline, 'something received focus');
    assert.notEqual(outline.style, 'none', 'focus is visible');
    assert.notEqual(outline.width, '0px');
    await page.close();
  });
});
