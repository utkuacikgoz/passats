/**
 * E2E tests for PassATS — runs in DEV_MODE against the Express app.
 *
 * Usage: node --test test/e2e.test.js
 */
const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');

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

// Minimal valid DOCX — PK zip with word/ directory marker
function makeDocx() {
  // Real DOCX is a zip; we create a minimal buffer that passes magic byte check
  // but will fail mammoth parse. In dev mode, extractText falls back to mock text.
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

  it('GET /api/health without secret returns 200 in dev mode (no HEALTH_SECRET set)', async () => {
    // In DEV_MODE, HEALTH_SECRET is undefined so the check passes
    const res = await request.get('/api/health');
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'ok');
    assert.equal(res.body.devMode, true);
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
  it('rejects request without file (400)', async () => {
    const token = await getDevToken();
    const res = await request
      .post('/api/analyze')
      .set('x-passats-token', token);

    assert.equal(res.status, 400);
    assert.match(res.body.error, /no file/i);
  });

  it('rejects file with wrong mimetype (silently filtered by multer)', async () => {
    const token = await getDevToken();
    const res = await request
      .post('/api/analyze')
      .set('x-passats-token', token)
      .attach('cv', Buffer.from('not a real file'), { filename: 'resume.txt', contentType: 'text/plain' });

    // multer fileFilter rejects non-allowed mimetypes — file won't be attached
    assert.equal(res.status, 400);
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

describe('Security headers', () => {
  it('sets security headers on HTML responses', async () => {
    const res = await request.get('/');
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal(res.headers['x-frame-options'], 'DENY');
    assert.ok(res.headers['content-security-policy']);
    assert.ok(res.headers['strict-transport-security']);
    assert.ok(res.headers['referrer-policy']);
    assert.ok(res.headers['permissions-policy']);
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
