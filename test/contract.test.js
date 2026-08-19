/**
 * Content contracts — the invariants that keep marketing, markup, and server
 * constants from drifting apart.
 *
 * Each of these has already broken once: the FAQ structured data kept a previous
 * copy rewrite, the share card kept the one before that, the legal pages drifted
 * onto a different palette, and the job-description limit existed only as a
 * number in multer that nothing on the page mentioned.
 *
 * Usage: node --test test/contract.test.js
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

process.env.DEV_MODE = 'true';
delete process.env.VERCEL;
const app = require('../server');
const { extractFaq, buildFaqLd } = require('../scripts/sync-structured-data');

const ROOT = path.join(__dirname, '..');
const read = relative => fs.readFileSync(path.join(ROOT, relative), 'utf8');

const index = read('views/index.html');
const privacy = read('views/privacy.html');
const terms = read('views/terms.html');
const llms = read('public/llms.txt');

function jsonLdBlocks(html) {
  return [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)]
    .map(match => JSON.parse(match[1]));
}

describe('structured data matches the visible page', () => {
  it('every FAQ answer in the markup is the answer in the JSON-LD', () => {
    const visible = extractFaq(index);
    assert.ok(visible.length >= 5, 'the FAQ is still on the page');

    const faqLd = jsonLdBlocks(index).find(block => block['@type'] === 'FAQPage');
    assert.ok(faqLd, 'FAQPage block present');
    assert.deepEqual(faqLd, buildFaqLd(visible), 'run `npm run sync:seo` — the FAQ markup and its structured data disagree');
  });

  it('carries no HowTo block — Google retired those rich results', () => {
    assert.equal(jsonLdBlocks(index).some(block => block['@type'] === 'HowTo'), false);
  });

  it('describes only the analysis the model is allowed to perform', () => {
    // server.js rule 8 forbids claims about visual layout, because the model only
    // ever sees extracted text. Marketing copy must not promise more than that.
    const overclaims = /\btables?\b|\bcolumns?\b|\bgraphics\b|single[- ]column|exactly as an ATS would/i;
    for (const [name, blocks] of [['index', jsonLdBlocks(index)]]) {
      const text = JSON.stringify(blocks);
      assert.doesNotMatch(text, overclaims, `${name} structured data claims layout analysis that does not ship`);
    }
    assert.doesNotMatch(
      llms.split('## What PassATS does not do')[0],
      overclaims,
      'llms.txt claims layout analysis that does not ship'
    );
    assert.match(llms, /does not evaluate visual layout/i, 'llms.txt states the limitation explicitly');
  });

  it('leads the title with the category and keeps the differentiator in the description', () => {
    const title = index.match(/<title>([^<]+)<\/title>/)[1];
    assert.match(title, /ATS Resume Checker/i);
    assert.ok(title.length <= 60, `title is ${title.length} chars — keep it inside the SERP cut`);

    const description = index.match(/<meta name="description" content="([^"]+)"/)[1];
    assert.ok(description.length <= 160, `meta description is ${description.length} chars`);
    assert.match(description, /no account|no subscription/i);
  });
});

describe('one brand across every page a buyer checks', () => {
  it('serves design tokens from a single stylesheet', () => {
    const tokens = read('public/tokens.css');
    assert.match(tokens, /--accent: #D85D43;/);
    assert.match(tokens, /--score-low: var\(--danger\);/, 'a failing score must not use the action colour');
  });

  it('has no page-local palette left to drift', () => {
    for (const [name, html] of [['index', index], ['privacy', privacy], ['terms', terms]]) {
      assert.match(html, /<link rel="stylesheet" href="\/tokens\.css">/, `${name} links the shared tokens`);
      assert.doesNotMatch(html, /:root\s*\{[^}]*--accent:/, `${name} still defines its own --accent`);
    }
  });

  it('keeps a parody celebrity name out of the sample report', () => {
    assert.doesNotMatch(index, /Zuck/i);
  });
});

describe('the customer can always reach support', () => {
  const email = app.__test.SUPPORT_EMAIL;

  it('publishes the same address the server puts in failure messages', () => {
    for (const [name, html] of [['index', index], ['privacy', privacy], ['terms', terms]]) {
      assert.ok(html.includes(email), `${name} does not show ${email}`);
    }
    assert.ok(llms.includes(email), 'llms.txt does not show the support address');
  });

  it('quotes a searchable reference in the terminal failure message', () => {
    const message = app.__test.analysisSupportMessage('abc-123');
    assert.match(message, new RegExp(email.replace('.', '\\.')));
    assert.match(message, /abc-123/);
    assert.match(message, /refund/i);
  });

  it('states the refund route and the withdrawal waiver in the terms', () => {
    assert.match(terms, /right of withdrawal/i);
    assert.match(terms, /refund you in full/i);
    assert.match(terms, /governed by the laws of/i);
  });

  it('states controller, legal basis, retention, and rights in the privacy policy', () => {
    assert.match(privacy, /data controller is/i);
    assert.match(privacy, /Why we are allowed to process it/i);
    assert.match(privacy, /How long we keep things/i);
    assert.match(privacy, /Your rights/i);
    assert.match(privacy, /Standard Contractual Clauses/i);
  });

  it('dates both legal pages to the same revision', () => {
    const stamp = html => html.match(/<strong>Last updated:<\/strong>\s*([^<]+)</)[1].trim();
    assert.equal(stamp(privacy), stamp(terms));
  });
});

describe('limits are the same number everywhere', () => {
  it('renders the server job-description limit into the textarea', () => {
    const maxlength = Number(index.match(/id="jobDescInput"[^>]*maxlength="(\d+)"/)[1]);
    assert.equal(maxlength, app.__test.MAX_JOB_DESCRIPTION_CHARS);
  });

  it('gives the byte ceiling headroom over the character limit for multi-byte text', () => {
    assert.ok(
      app.__test.MAX_JOB_DESCRIPTION_BYTES > app.__test.MAX_JOB_DESCRIPTION_CHARS,
      'a job description with accented or CJK characters would fail the byte limit first'
    );
  });

  it('states the upload ceiling the server enforces', () => {
    assert.equal(app.__test.MAX_UPLOAD_BYTES, 5 * 1024 * 1024);
    assert.match(index, /Max 5 MB/);
  });
});

describe('accessibility affordances are present', () => {
  it('announces errors', () => {
    assert.equal((index.match(/role="alert" aria-live="assertive"/g) || []).length, 2);
  });

  it('honours a reduced-motion preference', () => {
    assert.match(index, /@media \(prefers-reduced-motion: reduce\)/);
  });

  it('gives keyboard focus a visible ring on every page', () => {
    for (const [name, html] of [['index', index], ['privacy', privacy], ['terms', terms]]) {
      assert.match(html, /:focus-visible\s*\{/, `${name} has no focus-visible style`);
    }
  });

  it('lets the customer keep the report', () => {
    assert.match(index, /@media print/);
    assert.match(index, /save-report-btn/);
  });
});

describe('the test runner covers every suite', () => {
  it('names each test file in a script', () => {
    // node --test runs files in parallel, and the Chromium suite starved the
    // others under load until they were split. Explicit lists are only safe if
    // nothing can be added without being wired in, so assert exactly that.
    const scripts = JSON.parse(read('package.json')).scripts;
    const wired = `${scripts['test:node']} ${scripts['test:browser']}`;
    const files = fs.readdirSync(path.join(ROOT, 'test')).filter(name => name.endsWith('.test.js'));
    for (const file of files) {
      assert.ok(wired.includes(`test/${file}`), `test/${file} is never run — add it to test:node or test:browser`);
    }
  });
});

describe('deployment configuration', () => {
  const vercel = JSON.parse(read('vercel.json'));

  it('sets a function timeout above the LLM budget', () => {
    const fn = vercel.functions['api/index.js'];
    assert.ok(fn, 'the function is declared so maxDuration can be set at all');
    assert.ok(
      fn.maxDuration * 1000 > app.__test.LLM_TIMEOUT_MS,
      `maxDuration ${fn.maxDuration}s must exceed LLM_TIMEOUT_MS ${app.__test.LLM_TIMEOUT_MS}ms, or the platform kills the request outside our catch block`
    );
  });

  it('does not use the legacy builds array, which silently blocks functions config', () => {
    assert.equal(vercel.builds, undefined);
  });

  it('bundles the HTML the function serves', () => {
    assert.match(vercel.functions['api/index.js'].includeFiles, /views/);
  });

  it('keeps rendered HTML out of the static root so security headers always apply', () => {
    for (const page of ['index.html', 'privacy.html', 'terms.html']) {
      assert.equal(fs.existsSync(path.join(ROOT, 'public', page)), false, `public/${page} would be served header-free`);
      assert.equal(fs.existsSync(path.join(ROOT, 'views', page)), true);
    }
  });

  it('runs CI on the Node version it deploys', () => {
    // .nvmrc is the single source: CI reads it, nvm reads it, and Vercel resolves
    // `engines` to the newest release of that major. Asserting the two agree is
    // what stops CI going green about a runtime that never serves a request.
    const engines = JSON.parse(read('package.json')).engines.node;
    const pinned = read('.nvmrc').trim();
    const ci = read('.github/workflows/ci.yml');

    assert.match(ci, /node-version-file: \.nvmrc/, 'CI must read .nvmrc, not inline a version');
    assert.doesNotMatch(ci, /node-version: "/, 'an inlined version would drift from .nvmrc');
    assert.equal(pinned.split('.')[0], engines.split('.')[0], '.nvmrc and engines disagree on the major');
  });

  it('pins a Node version every dependency accepts', () => {
    // posthog-node declares ^20.20.0 || >=22.22.0. Anything below that floor
    // installs with an EBADENGINE warning and is unsupported by the vendor.
    const [major, minor] = read('.nvmrc').trim().split('.').map(Number);
    assert.ok(major > 22 || (major === 22 && minor >= 22), '.nvmrc is below the posthog-node floor of 22.22.0');
  });
});
