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

describe('the measurement tags are on every page and the CSP permits them', () => {
  // The CSP has no 'unsafe-inline' and no wildcard. A third-party tag whose
  // origin is not named does not degrade — it is blocked in the browser and
  // reports nothing, while the tag vendor's own preview still shows it firing.
  // Both halves are asserted here because either alone passes while broken.
  const pages = [
    'views/index.html', 'views/privacy.html', 'views/terms.html',
    'views/checklist.html', 'views/parse-preview.html', 'views/404.html',
    'views/guides/resume-keywords.html', 'views/guides/ats-parsing-errors.html',
  ];

  it('ships every tag on every page', () => {
    for (const page of pages) {
      const html = read(page);
      assert.match(html, /<script src="\/gtm\.js"><\/script>/, `${page} is missing the GTM loader`);
      assert.match(html, /<script src="\/gtag\.js"><\/script>/, `${page} is missing the Ads tag`);
      assert.match(html, /analytics\.ahrefs\.com\/analytics\.js/, `${page} is missing the Ahrefs tag`);
      assert.match(html, /googletagmanager\.com\/ns\.html\?id=GTM-/, `${page} is missing the GTM noscript fallback`);
    }
  });

  it('keeps the tag init out of inline blocks, where its hash would go stale', () => {
    // sync-csp-hashes.js only reads views/index.html, so an inline tag on any
    // other page could never be hashed. Shipping the init from public/ is what
    // makes one policy work for fifteen pages.
    for (const file of ['public/gtag.js', 'public/gtm.js']) {
      assert.ok(read(file).length > 0, `${file} is missing`);
    }
    for (const page of pages) {
      assert.doesNotMatch(read(page), /gtag\('config'/, `${page} inlines the Ads config instead of loading the file`);
      assert.doesNotMatch(read(page), /gtm\.start/, `${page} inlines the GTM loader instead of loading the file`);
    }
  });

  it('names every origin those tags actually reach', async () => {
    // Read the policy off a real response rather than grepping server.js: the
    // first cut of this test matched a comment that mentioned script-src and
    // passed against a policy it had never actually looked at. The header the
    // browser receives is the only thing that decides whether a tag runs.
    const server = app.listen(0);
    await new Promise(resolve => server.once('listening', resolve));
    try {
      const response = await fetch(`http://127.0.0.1:${server.address().port}/`);
      const policy = Object.fromEntries(
        response.headers.get('content-security-policy').split('; ')
          .map(part => [part.split(' ')[0], part]),
      );

      assert.match(policy['script-src'], /https:\/\/www\.googletagmanager\.com/, 'gtm.js and gtag/js load from here');
      assert.match(policy['script-src'], /https:\/\/analytics\.ahrefs\.com/);
      // googletagmanager.com is only where the tag starts. These two were
      // missing on the first attempt, so the tag loaded and every conversion
      // request it went on to make was blocked — visible only on CI, which has
      // real network. Named explicitly so that regression cannot repeat.
      assert.match(policy['script-src'], /https:\/\/googleads\.g\.doubleclick\.net/, 'gtag loads its conversion script from here');
      assert.match(policy['connect-src'], /https:\/\/ad\.doubleclick\.net/, 'gtag beacons its collect call here');
      assert.match(policy['connect-src'], /https:\/\/www\.google-analytics\.com/, 'the tag beacons here');
      assert.match(policy['connect-src'], /https:\/\/analytics\.ahrefs\.com/);
      // Without this the GTM noscript iframe falls to default-src 'self'.
      assert.match(policy['frame-src'], /https:\/\/www\.googletagmanager\.com/);
      assert.match(policy['img-src'], /https:\/\/www\.google\.com/, 'Ads conversion pixels are images');
      assert.doesNotMatch(policy['script-src'], /'unsafe-inline'/, 'adding a tag must never be paid for with unsafe-inline');

      // The two requests CI caught the browser blocking, kept as literal
      // fixtures. This sandbox has no route to Google, so the real tag cannot
      // run here and the failure was invisible until CI. Checking the actual
      // URLs against the actual policy is the part that can be verified without
      // a network, and it is the part that was wrong.
      const allows = (directive, url) => {
        const origin = new URL(url).origin;
        return policy[directive].split(' ').slice(1).includes(origin);
      };
      assert.ok(
        allows('script-src', 'https://googleads.g.doubleclick.net/pagead/viewthroughconversion/18417603742/?en=gtag.config'),
        'the conversion script CI saw blocked is still not allowed',
      );
      assert.ok(
        allows('connect-src', 'https://ad.doubleclick.net/ccm/s/collect?fmt=8'),
        'the collect beacon CI saw blocked is still not allowed',
      );
    } finally {
      await new Promise(resolve => server.close(resolve));
    }
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

describe('the development mock models the real product', () => {
  // Developers and the owner UI smoke test look at this report constantly. If it
  // breaks the rules the system prompt enforces, it teaches the wrong standard
  // and hides copy regressions behind plausible-looking output.
  const mockText = JSON.stringify(app.__test.devReport());

  it('uses none of the hedging phrases the prompt bans', () => {
    for (const banned of ['consider', 'it appears', 'seems like', 'you might want to', 'overall', 'in order to', 'leverage', 'utilize']) {
      assert.doesNotMatch(mockText, new RegExp(`\\b${banned}\\b`, 'i'), `mock report uses the banned phrase "${banned}"`);
    }
  });

  it('makes no claim about visual layout', () => {
    assert.doesNotMatch(mockText, /\btables?\b|\bcolumns?\b|\bgraphics\b|clean layout|single[- ]column/i);
  });

  it('uses no dash characters in customer-facing prose', () => {
    assert.doesNotMatch(mockText, /[\u2013\u2014]|--/);
  });

  it('returns 3 to 5 fixes and 3 to 7 issues, as the prompt requires', () => {
    const report = app.__test.devReport();
    assert.ok(report.topFixes.length >= 3 && report.topFixes.length <= 5, `${report.topFixes.length} fixes`);
    assert.ok(report.issues.length >= 3 && report.issues.length <= 7, `${report.issues.length} issues`);
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

/**
 * Colour contrast, pinned numerically.
 *
 * An external axe audit found eight failing nodes on the landing page: the
 * brand coral is only 3.27:1 on --bg, 3.69:1 on --card and 3.77:1 behind white,
 * all under the 4.5:1 that WCAG AA asks of text below 24px. The palette now
 * carries --accent-strong for those, and --accent stays on large display text
 * where the bar is 3:1 and the coral is the brand.
 *
 * These assertions compute the ratios rather than matching hex strings, because
 * the failure mode is someone retuning a token by eye and shipping a palette
 * that looks fine on their monitor and fails the audit again.
 */
function srgbToLinear(channel) {
  const c = channel / 255;
  return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
}

function relativeLuminance(hex) {
  const value = hex.replace('#', '');
  const full = value.length === 3 ? value.split('').map(c => c + c).join('') : value;
  const [r, g, b] = [0, 2, 4].map(i => srgbToLinear(parseInt(full.slice(i, i + 2), 16)));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrastRatio(foreground, background) {
  const [lighter, darker] = [relativeLuminance(foreground), relativeLuminance(background)]
    .sort((a, b) => b - a);
  return (lighter + 0.05) / (darker + 0.05);
}

function readTokens() {
  const css = read('public/tokens.css');
  const tokens = {};
  for (const [, name, value] of css.matchAll(/--([a-z-]+):\s*(#[0-9A-Fa-f]{3,8});/g)) {
    tokens[name] = value;
  }
  return tokens;
}

describe('text contrast meets WCAG AA wherever the brand coral is used', () => {
  const tokens = readTokens();
  const AA_TEXT = 4.5;   // under 24px, or under 18.66px bold
  const AA_LARGE = 3;    // 24px and up

  it('defines both coral tokens', () => {
    assert.equal(tokens.accent, '#D85D43', '--accent is the brand coral');
    assert.equal(tokens['accent-strong'], '#B93E24', '--accent-strong is the accessible coral');
  });

  it('--accent-strong clears 4.5:1 on every surface it is used on', () => {
    for (const surface of ['bg', 'card', 'accent-light']) {
      const ratio = contrastRatio(tokens['accent-strong'], tokens[surface]);
      // --accent-light is the pale chip behind the selected filename. It is
      // listed here to document that even --accent-strong does NOT clear 4.5:1
      // on it (4.28:1), which is why .file-selected takes --ink instead.
      if (surface === 'accent-light') {
        assert.ok(ratio < AA_TEXT, 'if --accent-light ever darkens enough for coral text, revisit .file-selected');
        continue;
      }
      assert.ok(ratio >= AA_TEXT, `--accent-strong on --${surface} is ${ratio.toFixed(2)}:1, under ${AA_TEXT}:1`);
    }
  });

  it('white and near-white labels clear 4.5:1 on an --accent-strong fill', () => {
    for (const label of ['#ffffff', tokens.card]) {
      const ratio = contrastRatio(label, tokens['accent-strong']);
      assert.ok(ratio >= AA_TEXT, `${label} on --accent-strong is ${ratio.toFixed(2)}:1, under ${AA_TEXT}:1`);
    }
  });

  it('keeps --accent usable for the large display text it is still on', () => {
    // The hero word and the step numerals are 32px and up, where the bar is 3:1.
    assert.ok(contrastRatio(tokens.accent, tokens.bg) >= AA_LARGE);
    assert.ok(contrastRatio(tokens.accent, tokens.card) >= AA_LARGE);
  });

  it('keeps the coral on the dark tips panel light, not dark', () => {
    // The inverse case, and the one a blanket find-and-replace gets wrong:
    // against --ink the ORIGINAL coral passes at 4.52:1 and --accent-strong
    // fails at 3.07:1. .tip-num must keep --accent-warm.
    assert.ok(
      contrastRatio(tokens.accent, tokens.ink) >= AA_TEXT,
      '--accent no longer clears AA on --ink; .tip-num needs a different colour'
    );
    assert.ok(
      contrastRatio(tokens['accent-strong'], tokens.ink) < AA_TEXT,
      'if --accent-strong now clears AA on --ink this guard can go, but check .tip-num first'
    );
    assert.match(
      index.match(/\.tip-num \{[\s\S]*?\}/)[0],
      /var\(--accent-warm\)/,
      '.tip-num sits on the dark panel and must keep the lighter coral'
    );
  });

  it('uses --accent-strong for every sub-24px coral text and white-on-coral fill', () => {
    const required = {
      'views/index.html': [
        /\.logo span \{ color: var\(--accent-strong\); \}/,
        /\.btn-primary \{[\s\S]*?background: var\(--accent-strong\)/,
        /\.analyze-btn \{[\s\S]*?background: var\(--accent-strong\)/,
        /\.report-fix-num \{ color: var\(--accent-strong\)/,
        /\.report-impact \{\s*color: var\(--accent-strong\)/,
      ],
      'views/404.html': [
        /\.logo span \{ color: var\(--accent-strong\); \}/,
        /background: var\(--accent-strong\); color: var\(--card\)/,
        /footer a \{ color: var\(--accent-strong\); \}/,
      ],
      'views/parse-preview.html': [/a \{ color: var\(--accent-strong\); \}/, /\.status-error \{ color: var\(--accent-strong\)/],
      'views/checklist.html': [/a \{ color: var\(--accent-strong\); \}/],
      'views/privacy.html': [/a \{ color: var\(--accent-strong\); \}/],
      'views/terms.html': [/a \{ color: var\(--accent-strong\); \}/],
      // The guide pages are generated; the template is the thing to pin.
      'scripts/build-guides.js': [
        /a \{ color: var\(--accent-strong\); \}/,
        /\.cta a\.btn \{[^}]*background: var\(--accent-strong\)/,
      ],
    };
    for (const [file, patterns] of Object.entries(required)) {
      const source = read(file);
      for (const pattern of patterns) {
        assert.match(source, pattern, `${file} regressed to the low-contrast coral`);
      }
    }
  });

  it('carries no opacity on the step numerals', () => {
    // opacity: 0.6 blended --accent down to #e89d8b — 2.13:1, under even the
    // 3:1 large-text bar. A token cannot guarantee contrast through a blend.
    assert.doesNotMatch(index.match(/\.step-num \{[\s\S]*?\}/)[0], /opacity/);
  });

  it('does not put coral text on the pale coral chip', () => {
    assert.match(index.match(/\.file-selected \{[\s\S]*?\}/)[0], /color: var\(--ink\)/);
  });

  it('tints the button shadows from the fill they sit under', () => {
    assert.doesNotMatch(index, /rgba\(216,93,67/, 'shadow still tinted from the old coral');
    assert.match(index, /rgba\(185,62,36/);
  });

  it('dims the loading steps with colour, not with alpha', () => {
    // opacity: 0.3 took --muted down to 1.48:1 — the worst ratio on the site,
    // on the one screen where that text is the only sign the upload is alive.
    const rule = index.match(/\.loading-step \{[\s\S]*?\}/)[0];
    assert.doesNotMatch(rule, /opacity/, 'a pending step is text a customer reads, not decoration');
    assert.match(rule, /color: var\(--muted\)/);
    assert.match(index, /\.loading-step\.done \{[^}]*color: var\(--ink\)/);
    assert.ok(contrastRatio(tokens.muted, tokens.bg) >= AA_TEXT, 'pending step colour must clear AA');
    assert.ok(contrastRatio(tokens.ink, tokens.bg) >= AA_TEXT, 'done step colour must clear AA');
  });

  it('keeps the semantic status colours readable on their own tints', () => {
    // The verdict badge and the metric scores are the report a customer paid
    // for. These pairs already passed; asserting them stops a future palette
    // tweak from quietly breaking the one screen behind the paywall, which no
    // crawler-based audit ever reaches.
    const verdicts = {
      'verdict-good': { fg: tokens.positive, bg: tokens['positive-light'] },
      'verdict-mid': { fg: index.match(/\.verdict-mid \{[^}]*color: (#[0-9A-Fa-f]{6})/)[1], bg: tokens['warning-light'] },
      'verdict-low': { fg: index.match(/\.verdict-low \{[^}]*color: (#[0-9A-Fa-f]{6})/)[1], bg: tokens['danger-light'] },
    };
    for (const [name, pair] of Object.entries(verdicts)) {
      const ratio = contrastRatio(pair.fg, pair.bg);
      assert.ok(ratio >= AA_TEXT, `.${name} is ${ratio.toFixed(2)}:1 on its tint, under ${AA_TEXT}:1`);
    }
    // The metric numerals are 32px, so the bar is 3:1.
    for (const status of ['positive', 'warning', 'danger']) {
      const ratio = contrastRatio(tokens[status], tokens.card);
      assert.ok(ratio >= AA_LARGE, `--${status} is ${ratio.toFixed(2)}:1 on --card, under ${AA_LARGE}:1`);
    }
  });
});

describe('the JSON-LD blocks form one connected graph', () => {
  // The blocks were three disconnected islands, which is what an AEO audit
  // reads as zero graph connectivity. They now hang off one Organization node.
  // Nothing here asserts a fact the site does not already state — no author,
  // no dates, no ratings.
  const blocks = jsonLdBlocks(index);
  const ids = new Set(blocks.map(block => block['@id']).filter(Boolean));

  it('gives every block a unique @id', () => {
    assert.equal(ids.size, blocks.length, 'every JSON-LD block needs its own @id');
  });

  it('names one Organization with a logo that actually ships', () => {
    const org = blocks.find(block => block['@type'] === 'Organization');
    assert.ok(org, 'Organization node present');
    assert.ok(org['@id'] && org.name && org.url, 'Organization needs @id, name and url');
    const logo = new URL(org.logo);
    assert.equal(fs.existsSync(path.join(ROOT, 'public', path.basename(logo.pathname))), true,
      `${org.logo} is referenced by the schema but not in public/`);
  });

  it('connects every other block to it, with no dangling references', () => {
    const org = blocks.find(block => block['@type'] === 'Organization')['@id'];
    const edgeOf = type => {
      const block = blocks.find(b => b['@type'] === type);
      assert.ok(block, `${type} block present`);
      return block;
    };
    assert.equal(edgeOf('WebSite').publisher['@id'], org);
    assert.equal(edgeOf('SoftwareApplication').provider['@id'], org);
    assert.equal(edgeOf('FAQPage').isPartOf['@id'], edgeOf('WebSite')['@id']);

    for (const block of blocks) {
      for (const key of ['publisher', 'provider', 'isPartOf']) {
        if (!block[key]) continue;
        assert.ok(ids.has(block[key]['@id']),
          `${block['@type']}.${key} points at ${block[key]['@id']}, which no block defines`);
      }
    }
  });

  it('claims no authorship, dates or ratings that the page cannot support', () => {
    const invented = /"(author|datePublished|dateModified|aggregateRating|review|reviewCount|ratingValue)"/;
    assert.doesNotMatch(JSON.stringify(blocks), invented,
      'a schema fact the page does not state is worse than a low audit score');
  });
});
