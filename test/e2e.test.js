/**
 * E2E tests for PassATS — runs in DEV_MODE against the Express app.
 *
 * Usage: node --test test/e2e.test.js
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

// Boot in dev mode
process.env.DEV_MODE = 'true';
delete process.env.VERCEL;

const app = require('../server');
const supertest = require('supertest');
const request = supertest(app);

// ── Helpers ──────────────────────────────────────────────────────────────────

// Minimal valid PDF (text-based, parseable)
function makePdf(text) {
  const content = text || 'John Doe\njohn@example.com\n555-1234\nSoftware Engineer with 5 years experience in JavaScript, React, Node.js, SQL, Git.';
  const stream = `1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n4 0 obj<</Length ${content.length + 20}>>stream\nBT /F1 12 Tf (${content}) Tj ET\nendstream\nendobj\n5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n`;
  const xrefOffset = stream.length;
  const pdf = `%PDF-1.4\n${stream}xref\n0 6\n0000000000 65535 f \ntrailer<</Size 6/Root 1 0 R>>\nstartxref\n${xrefOffset}\n%%EOF`;
  return Buffer.from(pdf);
}

// Minimal DOCX-like ZIP header; dev mode falls back to mock text after parsing.
function makeDocx() {
  // This passes the container check but fails Mammoth's structure validation.
  const buf = Buffer.alloc(2048);
  buf[0] = 0x50; buf[1] = 0x4B; buf[2] = 0x03; buf[3] = 0x04;
  buf.write('word/', 30);
  return buf;
}

async function getDevToken() {
  const res = await request.get('/api/dev-token');
  assert.equal(res.status, 200);
  assert.ok(res.body.token);
  return res.body.token;
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('Health & Static', () => {
  it('GET / returns HTML', async () => {
    const res = await request.get('/');
    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /html/);
  });

  it('GET /privacy returns HTML', async () => {
    const res = await request.get('/privacy');
    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /html/);
  });

  it('GET /terms returns HTML', async () => {
    const res = await request.get('/terms');
    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /html/);
  });

  it('GET /robots.txt returns text', async () => {
    const res = await request.get('/robots.txt');
    assert.equal(res.status, 200);
    assert.match(res.text, /User-agent/);
  });

  it('GET /api/health without secret returns 404 (HEALTH_SECRET always required)', async () => {
    // Health endpoint returns 404 when HEALTH_SECRET is not configured — never publicly accessible
    const res = await request.get('/api/health');
    assert.equal(res.status, 404);
  });

  it('GET /api/health with correct secret returns 200', async () => {
    process.env.HEALTH_SECRET = 'test-health-secret';
    const res = await request.get('/api/health').set('x-health-secret', 'test-health-secret');
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'ok');
    assert.equal(res.body.devMode, true);
    delete process.env.HEALTH_SECRET;
  });
});

describe('Checkout flow (dev mode)', () => {


  it('POST /api/checkout returns redirect URL', async () => {
    const res = await request.post('/api/checkout');
    assert.equal(res.status, 200);
    assert.ok(res.body.url);
    assert.match(res.body.url, /session_id=/);
  });

  it('GET /api/verify-payment with dev session_id returns token', async () => {
    const checkout = await request.post('/api/checkout');
    const url = new URL(checkout.body.url);
    const sessionId = url.searchParams.get('session_id');

    const res = await request.get(`/api/verify-payment?session_id=${sessionId}`);
    assert.equal(res.status, 200);
    assert.ok(res.body.token);
  });

  it('GET /api/verify-payment without session_id returns 400', async () => {
    const res = await request.get('/api/verify-payment');
    assert.equal(res.status, 400);
  });

  it('GET /api/dev-token returns a token', async () => {
    const token = await getDevToken();
    assert.ok(token.length > 20);
  });
});

describe('Analyze endpoint — happy path', () => {
  it('POST /api/analyze with valid token + file returns ATS report', async () => {
    const token = await getDevToken();
    const pdf = makePdf();

    const res = await request
      .post('/api/analyze')
      .set('x-passats-token', token)
      .attach('cv', pdf, 'resume.pdf');

    assert.equal(res.status, 200);
    assert.equal(typeof res.body.overallScore, 'number');
    assert.ok(res.body.verdict);
    assert.ok(res.body.verdictDetail);
    assert.ok(res.body.detectedRole);
    assert.ok(res.body.metrics);
    assert.ok(Array.isArray(res.body.issues));
    assert.ok(Array.isArray(res.body.keywordsFound));
    assert.ok(Array.isArray(res.body.keywordsMissing));
    assert.ok(Array.isArray(res.body.topFixes));
  });

  it('POST /api/analyze with DOCX returns ATS report', async () => {
    const token = await getDevToken();
    const docx = makeDocx();

    const res = await request
      .post('/api/analyze')
      .set('x-passats-token', token)
      .attach('cv', docx, { filename: 'resume.docx', contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });

    assert.equal(res.status, 200);
    assert.equal(typeof res.body.overallScore, 'number');
  });

  it('POST /api/analyze with job description succeeds', async () => {
    const token = await getDevToken();
    const pdf = makePdf();

    const res = await request
      .post('/api/analyze')
      .set('x-passats-token', token)
      .attach('cv', pdf, 'resume.pdf')
      .field('jobDescription', 'Senior Software Engineer. Must have 5+ years experience with React, Node.js, AWS, Docker.');

    assert.equal(res.status, 200);
    assert.equal(typeof res.body.overallScore, 'number');
  });
});

describe('Analyze endpoint — token security', () => {
  it('rejects request without token (401)', async () => {
    const pdf = makePdf();
    const res = await request
      .post('/api/analyze')
      .attach('cv', pdf, 'resume.pdf');

    assert.equal(res.status, 401);
    assert.match(res.body.error, /missing token/i);
  });

  it('rejects request with garbage token (401)', async () => {
    const pdf = makePdf();
    const res = await request
      .post('/api/analyze')
      .set('x-passats-token', 'not-a-real-token')
      .attach('cv', pdf, 'resume.pdf');

    assert.equal(res.status, 401);
    assert.match(res.body.error, /invalid|expired/i);
  });

  it('rejects second use of same token (403)', async () => {
    const token = await getDevToken();
    const pdf = makePdf();

    // First use — should succeed
    const res1 = await request
      .post('/api/analyze')
      .set('x-passats-token', token)
      .attach('cv', pdf, 'resume.pdf');
    assert.equal(res1.status, 200);

    // Second use — should be blocked
    const res2 = await request
      .post('/api/analyze')
      .set('x-passats-token', token)
      .attach('cv', pdf, 'resume.pdf');
    assert.equal(res2.status, 403);
    assert.match(res2.body.error, /already used/i);
  });
});

describe('Analyze endpoint — file validation', () => {
  it('names the real problem when the file type is rejected, and does not burn the payment', async () => {
    const token = await getDevToken();
    const res = await request
      .post('/api/analyze')
      // Own rate-limit bucket: this suite shares the default IP and the analyze
      // limiter is 10/min, so an extra request here would 429 a later test.
      .set('x-forwarded-for', '198.51.100.31')
      .set('x-passats-token', token)
      .attach('cv', Buffer.from('GIF89a still not a resume'), { filename: 'cv.gif', contentType: 'image/gif' });

    // multer drops a filtered file silently, so this used to surface as
    // "No file uploaded" — true of req.file, but not of what the customer did.
    assert.equal(res.status, 415);
    assert.match(res.body.error, /file type is not supported/i);
    assert.doesNotMatch(res.body.error, /no file uploaded/i);
  });

  it('rejects request without file (400)', async () => {
    const token = await getDevToken();
    const res = await request
      .post('/api/analyze')
      .set('x-passats-token', token);

    assert.equal(res.status, 400);
    assert.match(res.body.error, /no file/i);
  });

  it('rejects a wrong mimetype with an unsupported-type status, not a generic 400', async () => {
    const token = await getDevToken();
    const res = await request
      .post('/api/analyze')
      .set('x-passats-token', token)
      .attach('cv', Buffer.from('not a real file'), { filename: 'resume.txt', contentType: 'text/plain' });

    // multer's fileFilter still drops the file; the handler now distinguishes
    // "you sent a type we cannot read" from "you sent nothing at all".
    assert.equal(res.status, 415);
    assert.match(res.body.error, /PDF or a DOCX/i);
  });

  it('rejects legacy DOC uploads that the parser does not support', async () => {
    const token = await getDevToken();
    const legacyDoc = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0x00, 0x00]);
    const res = await request
      .post('/api/analyze')
      .set('x-forwarded-for', '198.51.100.22')
      .set('x-passats-token', token)
      .attach('cv', legacyDoc, { filename: 'resume.doc', contentType: 'application/msword' });

    // .doc is a different format from .docx, not a corrupt .docx — say so.
    assert.equal(res.status, 415);
    assert.match(res.body.error, /PDF or a DOCX/i);
  });

  it('rejects file with valid mimetype but wrong magic bytes', async () => {
    const token = await getDevToken();
    const fakePdf = Buffer.from('this is not a real PDF file but it pretends to be one with enough bytes');

    const res = await request
      .post('/api/analyze')
      .set('x-passats-token', token)
      .attach('cv', fakePdf, { filename: 'resume.pdf', contentType: 'application/pdf' });

    assert.equal(res.status, 400);
    assert.match(res.body.error, /does not match/i);
  });
});

describe('Rate limiting', () => {
  it('blocks excessive checkout requests', async () => {
    const results = [];
    // Send 12 requests — limit is 10/min
    for (let i = 0; i < 12; i++) {
      results.push(await request.post('/api/checkout'));
    }
    const blocked = results.filter(r => r.status === 429);
    assert.ok(blocked.length > 0, 'Expected at least one 429 response');
  });
});

describe('Coupon codes are off unless configured', () => {
  it('rejects every code when COUPON_CODES is unset', async () => {
    // Default-off matters more here than anywhere else in the app: a coupon
    // endpoint that works without configuration hands out the product free.
    assert.equal(process.env.COUPON_CODES, undefined, 'this suite must run unconfigured');
    for (const code of ['', 'TEST', 'FRIENDS', 'constructor', '__proto__']) {
      const res = await request.post('/api/redeem-coupon').send({ code });
      assert.equal(res.status, 404, `code ${JSON.stringify(code)} must not redeem`);
      assert.equal(res.body.token, undefined);
    }
  });

  it('does not mint a token for a prototype key', async () => {
    // matchCoupon walks real entries rather than indexing an object, so a
    // prototype key cannot resolve to something truthy.
    assert.equal(app.__test.matchCoupon('CONSTRUCTOR'), null);
    assert.equal(app.__test.matchCoupon('__PROTO__'), null);
  });
});

describe('Security headers', () => {
  it('does not advertise the framework, and locks form submission to this origin', async () => {
    const res = await request.get('/');
    assert.equal(res.headers['x-powered-by'], undefined, 'X-Powered-By names the framework on every response');
    // default-src does not cover form-action, so an omission here is silent:
    // injected markup could post a form to an attacker's origin.
    assert.match(res.headers['content-security-policy'], /form-action 'self'/);
  });

  it('sets security headers on HTML responses', async () => {
    const res = await request.get('/');
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal(res.headers['x-frame-options'], 'DENY');
    assert.ok(res.headers['content-security-policy']);
    assert.ok(res.headers['strict-transport-security']);
    assert.ok(res.headers['referrer-policy']);
    assert.ok(res.headers['permissions-policy']);
  });

  it('authorizes every executable inline script and event handler in CSP', async () => {
    const res = await request.get('/');
    const csp = res.headers['content-security-policy'];
    const hash = body => `sha256-${crypto.createHash('sha256').update(body).digest('base64')}`;

    for (const match of res.text.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)) {
      const [, attributes, body] = match;
      if (!attributes.includes('application/ld+json') && body.trim()) {
        assert.ok(csp.includes(hash(body)), `CSP missing inline script hash: ${hash(body)}`);
      }
    }

    const handlers = new Set([...res.text.matchAll(/\s(on[a-z]+)="([^"]*)"/g)].map(match => match[2]));
    for (const body of handlers) {
      assert.ok(csp.includes(hash(body)), `CSP missing inline handler hash: ${hash(body)}`);
    }
  });

  it('sets no-store on API responses', async () => {
    const res = await request.get('/api/verify-payment?session_id=test');
    assert.match(res.headers['cache-control'], /no-store/);
  });
});

describe('Webhook', () => {
  it('POST /api/webhook returns received in dev mode', async () => {
    const res = await request
      .post('/api/webhook')
      .set('Content-Type', 'application/json')
      .send(JSON.stringify({ type: 'checkout.session.completed' }));

    assert.equal(res.status, 200);
    assert.equal(res.body.received, true);
  });
});

describe('Removed email capture', () => {
  it('does not claim to send reports through an unimplemented endpoint', async () => {
    const res = await request.post('/api/capture-email').send({ email: 'person@example.com' });
    assert.equal(res.status, 404);
  });
});

describe('Customer-facing analysis failures', () => {
  it('shows the server message only for 4xx, and stays generic for 5xx', async () => {
    const res = await request.get('/');
    // 4xx bodies are written for the customer ("remove the PDF password") and are
    // the difference between a fixable problem and a dead end. 5xx bodies can
    // carry internals, so those are replaced with the generic line.
    assert.match(res.text, /err\.userFacing = res\.status >= 400 && res\.status < 500/);
    assert.match(res.text, /err && err\.userFacing/);
    assert.match(res.text, /We couldn\\'t complete your analysis just now\. Please try again in a moment\./);
    assert.doesNotMatch(res.text, /Analysis failed: ' \+ err\.message/);
  });
});

describe('Upload limits return actionable JSON', () => {
  it('rejects an oversized file with 413 JSON, not an HTML error page', async () => {
    const token = await getDevToken();
    // Just over the 5 MB ceiling: large enough to trip multer, small enough that
    // the request body finishes before the server closes the socket.
    const oversized = Buffer.concat([Buffer.from('%PDF-'), Buffer.alloc(5 * 1024 * 1024)]);
    const res = await request
      .post('/api/analyze')
      .set('x-vercel-forwarded-for', '198.51.100.201')
      .set('x-passats-token', token)
      .attach('cv', oversized, { filename: 'big.pdf', contentType: 'application/pdf' });

    assert.equal(res.status, 413);
    assert.match(res.headers['content-type'], /application\/json/);
    assert.match(res.body.error, /larger than 5 MB/i);
  });

  it('rejects an oversized job description with 413 JSON', async () => {
    const token = await getDevToken();
    const res = await request
      .post('/api/analyze')
      .set('x-vercel-forwarded-for', '198.51.100.202')
      .set('x-passats-token', token)
      .field('jobDescription', 'J'.repeat(25000))
      .attach('cv', makePdf(), { filename: 'cv.pdf', contentType: 'application/pdf' });

    assert.equal(res.status, 413);
    assert.match(res.headers['content-type'], /application\/json/);
    assert.match(res.body.error, /job description is too long/i);
  });
});

describe('Client funnel events', () => {
  const anon = '3f2504e0-4f89-11d3-9a0c-0305e82c3301';

  it('accepts an allowlisted event', async () => {
    const res = await request.post('/api/event').send({ event: 'landing_viewed', anonymousId: anon });
    assert.equal(res.status, 204);
  });

  it('rejects an event name that is not on the list', async () => {
    const res = await request.post('/api/event').send({ event: 'resume_text', anonymousId: anon });
    assert.equal(res.status, 400);
  });

  it('rejects a malformed anonymous id', async () => {
    const res = await request.post('/api/event').send({ event: 'landing_viewed', anonymousId: 'person@example.com' });
    assert.equal(res.status, 400);
  });

  it('ignores any extra properties a caller tries to attach', async () => {
    // An open property bag is how resume text reaches an analytics tool by
    // accident. The endpoint takes a name and an id, and nothing else.
    const res = await request.post('/api/event').send({
      event: 'report_viewed',
      anonymousId: anon,
      properties: { cvText: 'John Doe, Software Engineer' },
    });
    assert.equal(res.status, 204);
    assert.equal(res.text, '');
  });

  it('covers the whole funnel, with no event that could carry content', async () => {
    const events = [...app.__test.CLIENT_EVENTS];
    for (const step of ['landing_viewed', 'checkout_clicked', 'upload_view_reached', 'analysis_started', 'report_viewed']) {
      assert.ok(events.includes(step), `funnel is missing ${step}`);
    }
    for (const name of events) {
      assert.match(name, /^[a-z_]+$/, `${name} should be a fixed step name`);
    }
  });
});

describe('Routing', () => {
  it('404s an unknown API route as JSON instead of returning the landing page', async () => {
    const res = await request.get('/api/definitely-not-a-route');
    assert.equal(res.status, 404);
    assert.match(res.headers['content-type'], /application\/json/);
    assert.equal(res.body.error, 'Not found');
  });

  it('404s a missing asset instead of answering 200 with HTML', async () => {
    const res = await request.get('/_vercel/insights/script.js');
    assert.equal(res.status, 404);
    assert.doesNotMatch(res.headers['content-type'] || '', /html/);
  });

  it('404s unknown pages instead of serving the app shell', async () => {
    // A catch-all that returned the landing page answered 200 for /jobs, /blog,
    // and every other guessed path: an unbounded set of soft-404s competing with
    // the real pages in search results.
    for (const route of ['/jobs', '/blog', '/a/b/c']) {
      const res = await request.get(route);
      assert.equal(res.status, 404, `${route} should not exist`);
      assert.match(res.text, /That page does not exist/);
      assert.match(res.text, /noindex/);
    }
  });

  it('still serves the real pages', async () => {
    for (const route of ['/', '/success', '/privacy', '/terms']) {
      assert.equal((await request.get(route)).status, 200, `${route} must be served`);
    }
  });

  it('301s the .html variants to their canonical clean paths', async () => {
    for (const [from, to] of [['/privacy.html', '/privacy'], ['/terms.html', '/terms'], ['/index.html', '/']]) {
      const res = await request.get(from);
      assert.equal(res.status, 301, `${from} should redirect`);
      assert.equal(res.headers.location, to);
    }
  });

  it('serves the shared design tokens', async () => {
    const res = await request.get('/tokens.css');
    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /text\/css/);
  });
});

describe('Owner UI testing', () => {
  it('accepts only a short-lived owner token from a URL fragment and removes it from history', async () => {
    const res = await request.get('/');
    assert.match(res.text, /owner_test_token/);
    assert.match(res.text, /payload\.sessionId\.startsWith\('test_'\)/);
    assert.match(res.text, /window\.history\.replaceState/);
  });
});
