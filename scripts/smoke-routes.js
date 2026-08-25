#!/usr/bin/env node
/**
 * Routing smoke check for a deployed origin.
 *
 * The app moved off Vercel's legacy `builds` array onto `functions` plus a
 * catch-all rewrite into api/index.js, because `maxDuration` cannot be set any
 * other way. That change is the one thing the test suite cannot prove: it
 * depends on Vercel preserving the original request path through the rewrite,
 * and on public/ still being served ahead of it. Run this against the first
 * preview deploy before promoting it.
 *
 * Usage:
 *   BASE=https://your-deployment.vercel.app npm run smoke:routes
 *   BASE=http://localhost:3000 npm run smoke:routes     # works locally too
 */
const BASE = (process.env.BASE || process.env.PASSATS_BASE_URL || 'http://localhost:3000').replace(/\/$/, '');

// Vercel Deployment Protection sits in front of preview URLs and answers every
// request with its own SSO page. Without a bypass the checks below prove nothing: they
// see Vercel's HTML, its CSP, and its redirects. Set a Protection Bypass for
// Automation secret (Project Settings, Deployment Protection) and pass it here.
const BYPASS = process.env.VERCEL_BYPASS_TOKEN || process.env.VERCEL_AUTOMATION_BYPASS_SECRET || '';
const HEADERS = BYPASS ? { 'x-vercel-protection-bypass': BYPASS, 'x-vercel-set-bypass-cookie': 'true' } : {};

const CHECKS = [
  {
    name: 'landing page is served by the function',
    path: '/',
    expect: { status: 200, type: /text\/html/, body: /ATS Resume Checker/ },
    // Proves the rewrite reached Express rather than a static file: only the
    // function sets these, and a CDN-served copy would arrive without them.
    headers: { 'content-security-policy': /sha256-/, 'x-frame-options': /DENY/ },
  },
  { name: 'privacy page routes', path: '/privacy', expect: { status: 200, body: /Privacy Policy/ } },
  { name: 'terms page routes', path: '/terms', expect: { status: 200, body: /Terms of Service/ } },
  { name: 'success page routes', path: '/success', expect: { status: 200, type: /text\/html/ } },
  { name: 'unknown page 404s with the branded page', path: '/some/deep/route', expect: { status: 404, type: /text\/html/, body: /That page does not exist/ } },

  { name: 'static asset bypasses the function', path: '/robots.txt', expect: { status: 200, body: /Disallow: \/api\// } },
  { name: 'shared design tokens are served', path: '/tokens.css', expect: { status: 200, type: /text\/css/ } },
  { name: 'sitemap is served', path: '/sitemap.xml', expect: { status: 200, body: /<urlset/ } },
  { name: 'OG image is served', path: '/og-image.png', expect: { status: 200, type: /image\/png/ } },

  { name: 'unknown API route 404s as JSON', path: '/api/definitely-not-a-route', expect: { status: 404, type: /application\/json/ }, api: true },
  { name: 'missing asset 404s instead of returning HTML', path: '/nope.js', expect: { status: 404, notType: /text\/html/ } },
  { name: 'health endpoint stays gated', path: '/api/health', expect: { status: 404 }, api: true },

  { name: '/privacy.html redirects', path: '/privacy.html', expect: { status: 301, location: '/privacy' }, redirect: 'manual' },
  { name: '/terms.html redirects', path: '/terms.html', expect: { status: 301, location: '/terms' }, redirect: 'manual' },
  { name: '/index.html redirects', path: '/index.html', expect: { status: 301, location: '/' }, redirect: 'manual' },
];

async function run(check) {
  const failures = [];
  let res;
  try {
    res = await fetch(BASE + check.path, { redirect: check.redirect || 'follow', headers: HEADERS });
  } catch (err) {
    return [`request failed: ${err.message}`];
  }

  const { expect } = check;
  // A 503 on /api/* is the app's deliberate degraded mode: it boots without
  // required config so the marketing pages stay up. Name that explicitly rather
  // than reporting it as a confusing status mismatch.
  if (check.api && res.status === 503) return ['DEGRADED'];
  if (expect.status && res.status !== expect.status) failures.push(`status ${res.status}, expected ${expect.status}`);

  const type = res.headers.get('content-type') || '';
  if (expect.type && !expect.type.test(type)) failures.push(`content-type "${type}" did not match ${expect.type}`);
  if (expect.notType && expect.notType.test(type)) failures.push(`content-type "${type}" should not match ${expect.notType}`);

  if (expect.location) {
    const location = res.headers.get('location');
    if (location !== expect.location) failures.push(`location "${location}", expected "${expect.location}"`);
  }

  for (const [header, pattern] of Object.entries(check.headers || {})) {
    const value = res.headers.get(header);
    if (!value || !pattern.test(value)) failures.push(`header ${header} was "${value}", expected ${pattern}`);
  }

  if (expect.body) {
    const text = await res.text();
    if (!expect.body.test(text)) failures.push(`body did not match ${expect.body}`);
  }

  return failures;
}

// Returns a reason string when the origin is gated, so 15 confusing failures are
// not reported as if the application were broken.
async function detectProtection() {
  try {
    const res = await fetch(BASE + '/robots.txt', { redirect: 'manual', headers: HEADERS });
    const location = res.headers.get('location') || '';
    if (/vercel\.com\/sso-api/.test(location)) return 'Vercel Deployment Protection (SSO)';
    if (res.status === 401) return 'the origin returned 401 Unauthorized';
    const cookies = res.headers.get('set-cookie') || '';
    if (/_vercel_sso_nonce/.test(cookies)) return 'Vercel Deployment Protection (SSO)';
  } catch { /* connection problems surface per-check below */ }
  return null;
}

(async () => {
  console.log(`Routing smoke check against ${BASE}\n`);

  const gate = await detectProtection();
  if (gate) {
    console.error(`Blocked by ${gate}.\n`);
    console.error('Every request is answered by the protection layer, so these checks');
    console.error('would report the gate rather than the application. Either:\n');
    console.error('  1. Project Settings > Deployment Protection > Protection Bypass for');
    console.error('     Automation, then re-run with VERCEL_BYPASS_TOKEN=<secret>, or');
    console.error('  2. disable protection for preview deployments, or');
    console.error('  3. run this against production once deployed.\n');
    process.exit(2);
  }
  let failed = 0;
  let degraded = false;

  for (const check of CHECKS) {
    const failures = await run(check);
    if (failures[0] === 'DEGRADED') {
      degraded = true;
      failed++;
      console.log(`  FAIL  ${check.path.padEnd(28)} ${check.name}`);
      console.log('          503 — the API is disabled');
      continue;
    }
    if (failures.length === 0) {
      console.log(`  PASS  ${check.path.padEnd(28)} ${check.name}`);
    } else {
      failed++;
      console.log(`  FAIL  ${check.path.padEnd(28)} ${check.name}`);
      for (const failure of failures) console.log(`          ${failure}`);
    }
  }

  console.log();
  if (degraded) {
    console.error('The API returned 503: this deployment booted without its required');
    console.error('environment variables, so routing cannot be fully verified. Set them');
    console.error('and re-run. The server logs name exactly which ones are missing.\n');
  }
  if (failed > 0) {
    console.error(`${failed} of ${CHECKS.length} checks failed. Do not promote this deployment.`);
    process.exit(1);
  }
  console.log(`All ${CHECKS.length} checks passed.`);
})();
