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

  it('survives a refresh when the session carries a real payment id', async () => {
    // The dev flow never calls saveSession, so STORE_KEY holds no sessionId and
    // the restore guard compares undefined to undefined. That passes for the
    // wrong reason and hid a live bug: a real purchase stores a sessionId, and
    // this asserts the report still comes back when one is present.
    //
    // It also covers the collision that shipped. STORE_KEY and ANON_KEY were
    // rewritten to the same value, so the analytics id overwrote the saved
    // report and JSON.parse threw on reload. Reading the store after a reload
    // proves the report survived rather than trusting the rendered view.
    const page = await browser.newPage();
    await runAnalysis(page);
    const scoreBefore = await page.textContent('#dashScoreNumber');

    const keys = await page.evaluate(() => {
      const store = 'passats.session.v1';
      const raw = sessionStorage.getItem(store);
      const parsed = raw ? JSON.parse(raw) : {};
      // Stamp a real payment id, the way handlePaymentReturn does.
      parsed.sessionId = 'cs_test_refresh';
      parsed.reportSessionId = 'cs_test_refresh';
      sessionStorage.setItem(store, JSON.stringify(parsed));
      return Object.keys(sessionStorage);
    });
    assert.ok(keys.length >= 2, `expected the report and the anonymous id under separate keys, saw ${keys.join(',')}`);

    await page.reload();
    await page.waitForSelector('#dashboard.active', { timeout: 10000 });
    assert.equal(await page.textContent('#dashScoreNumber'), scoreBefore, 'the paid report did not survive the refresh');

    const stillThere = await page.evaluate(() => {
      const raw = sessionStorage.getItem('passats.session.v1');
      try { return !!(raw && JSON.parse(raw).report); } catch { return false; }
    });
    assert.ok(stillThere, 'the stored report was clobbered by another writer');
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

  it('does not hand a repeat customer their previous report', async () => {
    // Regression: the stored report used to survive a second purchase, so a
    // refresh after paying again restored the old analysis and left the
    // customer unable to upload the CV they had just paid to have scored.
    const page = await browser.newPage();
    await runAnalysis(page);

    await page.goto(`${origin}/success?session_id=dev_second_purchase`);
    await page.waitForSelector('#upload.active', { timeout: 15000 });

    await page.reload();

    await page.waitForSelector('#upload.active', { timeout: 10000 });
    assert.equal(await page.isVisible('#dashboard.active'), false, 'the previous report must not come back');
    await page.close();
  });

  it('offers the report as a saveable document that identifies itself', async () => {
    const page = await browser.newPage();
    await runAnalysis(page);
    assert.equal(await page.isVisible('.save-report-btn'), true);

    // The printed copy is a document the customer keeps and may forward. It must
    // carry the mark, the file it covers, and a support route.
    await page.emulateMedia({ media: 'print' });
    assert.equal(await page.isVisible('.print-footnote'), true, 'printed report is anonymous');
    assert.equal(await page.isVisible('#dashFileName'), true, 'printed report loses the file and date');
    // Read from config rather than pinning a literal: this assertion went stale
    // the moment the domain moved, and a stale test is a false alarm at exactly
    // the moment you need the suite to be trustworthy.
    assert.match(await page.textContent('.print-footnote'), new RegExp(require('../config/site').SUPPORT_EMAIL.replace(/\./g, '\\.')));
    assert.equal(await page.isVisible('.cta-again'), false, 'buttons must not print');
    await page.emulateMedia({ media: 'screen' });

    // ...and must not clutter the screen view.
    assert.equal(await page.isVisible('.print-footnote'), false);
    await page.close();
  });
});

describe('the waiting room', () => {
  it('rotates reading material and stops the timer when the report arrives', async () => {
    const page = await browser.newPage();
    try {
      await page.goto(`${origin}/?dev=1`);
      await page.waitForSelector('#upload.active', { timeout: 15000 });
      await page.setInputFiles('#fileInput', cvPath);
      await page.click('#analyzeBtn');
      await page.waitForSelector('#loading.active', { timeout: 10000 });

      const seen = new Set();
      const poll = setInterval(async () => {
        try {
          const line = (await page.textContent('#loadingJoke') || '').trim();
          if (line) seen.add(line);
        } catch { /* page navigated */ }
      }, 250);

      await page.waitForSelector('#dashboard.active', { timeout: 40000 });
      clearInterval(poll);

      assert.ok(seen.size >= 2, `expected the line to change at least once, saw ${seen.size}`);

      // The real risk is a leaked setInterval ticking behind the report the
      // customer is reading. Both exits from startAnalysis leave the loading
      // view, so the text must be frozen once the dashboard is up.
      const settled = await page.textContent('#loadingJoke');
      await page.waitForTimeout(4200);
      assert.equal(await page.textContent('#loadingJoke'), settled, 'the rotation timer outlived the loading view');
    } finally {
      await page.close();
    }
  });

  it('gives the report a headline about the customer, not about the machine', async () => {
    const page = await browser.newPage();
    try {
      await runAnalysis(page);
      const heading = (await page.textContent('.dash-hero h2')).trim();
      assert.match(heading, /your best work/i);
      assert.doesNotMatch(heading, /robots see/i);
    } finally {
      await page.close();
    }
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
    // maxlength governs typing and paste, not programmatic assignment, so type
    // into the field rather than setting .value and assert the browser clipped it.
    await page.fill('#jobDescInput', '');
    await page.evaluate(() => {
      const input = document.getElementById('jobDescInput');
      input.focus();
      document.execCommand('insertText', false, 'x'.repeat(20000));
    });
    const length = await page.evaluate(() => document.getElementById('jobDescInput').value.length);
    assert.equal(length, app.__test.MAX_JOB_DESCRIPTION_CHARS, 'the browser enforced maxlength on input');
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
