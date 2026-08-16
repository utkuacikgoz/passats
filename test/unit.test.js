/**
 * Unit tests for PassATS pure helpers and the real (non-DEV_MODE) Claude path.
 *
 * Boots the app in production mode with dummy config so the analysis code path
 * is exercised with an injected fake Anthropic client — no network, no mocks of
 * the mock. Covers the gap left by e2e.test.js, which runs entirely in DEV_MODE.
 *
 * Usage: node --test test/unit.test.js
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const supertest = require('supertest');

// Boot in production mode with valid dummy config (no CONFIG_ERROR, no network).
delete process.env.DEV_MODE;
delete process.env.VERCEL;
delete process.env.TEST_SECRET;          // exercise the "gate closed" path
process.env.BASE_URL = 'https://test.passats.example';
process.env.STRIPE_SECRET_KEY = 'sk_test_dummy';
process.env.STRIPE_WEBHOOK_SECRET = 'whsec_dummy';
process.env.STRIPE_PRICE_ID = 'price_dummy';
process.env.ANTHROPIC_API_KEY = 'sk-ant-dummy';
process.env.JWT_SECRET = 'a'.repeat(64);
process.env.UPSTASH_REDIS_REST_URL = 'https://example.upstash.io';
process.env.UPSTASH_REDIS_REST_TOKEN = 'dummy-token';

const app = require('../server');
const {
  analyzeCv,
  sanitizeSchema,
  normalizeScore,
  validateMagicBytes,
  checkOrigin,
  safeSecretEqual,
  isOwnerTestAuthorized,
  claimAnalysis,
  hasAnalysisClaim,
  releaseAnalysisClaim,
  analysisClaimKey,
  analysisRetryKey,
  extractText,
  ATS_OUTPUT_SCHEMA,
  LLM_TIMEOUT_MS,
} = app.__test;

// A well-formed report the fake model returns; overallScore as 0-1 decimal to
// also assert normalization runs.
function validReport() {
  return {
    overallScore: 0.72,
    verdict: 'Needs Work',
    verdictDetail: 'x',
    detectedRole: 'Software Engineer',
    metrics: {
      keywords: { score: 0.65, note: 'x' },
      formatting: { score: 78, note: 'x' },
      readability: { score: 80, note: 'x' },
      contactInfo: { score: 90, note: 'x' },
    },
    issues: [{ severity: 'critical', title: 'x', detail: 'x' }],
    keywordsFound: ['JavaScript'],
    keywordsMissing: ['CI/CD'],
    topFixes: ['a', 'b', 'c', 'd', 'e'],
  };
}

// Minimal fake Anthropic client: messages.create returns/throws what each test needs.
function fakeClient(behavior) {
  return { messages: { create: async () => behavior() } };
}

describe('sanitizeSchema', () => {
  it('strips unsupported JSON-schema keywords but keeps structure', () => {
    const input = {
      type: 'object',
      additionalProperties: false,
      required: ['score', 'tags'],
      properties: {
        score: { type: 'number', minimum: 0, maximum: 100, description: 'keep me' },
        tags: { type: 'array', items: { type: 'string', maxLength: 5 }, maxItems: 3 },
        verdict: { type: 'string', enum: ['a', 'b'] },
      },
    };
    const out = sanitizeSchema(input);
    const s = JSON.stringify(out);
    for (const bad of ['minimum', 'maximum', 'maxItems', 'maxLength', 'minLength', 'pattern']) {
      assert.ok(!s.includes(bad), `should strip ${bad}`);
    }
    assert.equal(out.additionalProperties, false);
    assert.deepEqual(out.required, ['score', 'tags']);
    assert.deepEqual(out.properties.verdict.enum, ['a', 'b']);
    assert.equal(out.properties.score.description, 'keep me');
    assert.equal(out.properties.tags.items.type, 'string');
  });

  it('ATS_OUTPUT_SCHEMA has no unsupported keywords and retains strict-mode shape', () => {
    const s = JSON.stringify(ATS_OUTPUT_SCHEMA);
    assert.ok(!/minimum|maximum|maxItems|minLength|maxLength/.test(s));
    assert.equal(ATS_OUTPUT_SCHEMA.additionalProperties, false);
    assert.ok(Array.isArray(ATS_OUTPUT_SCHEMA.required));
  });
});

describe('normalizeScore', () => {
  it('scales 0-1 decimals to 0-100', () => {
    assert.equal(normalizeScore(0.72), 72);
    assert.equal(normalizeScore(0.05), 5);
    assert.equal(normalizeScore(1), 100);
  });
  it('rounds values already in 0-100 range', () => {
    assert.equal(normalizeScore(72), 72);
    assert.equal(normalizeScore(85.4), 85);
    assert.equal(normalizeScore(0), 0);
    assert.equal(normalizeScore(100), 100);
  });
  it('clamps out-of-range and invalid values', () => {
    assert.equal(normalizeScore(-5), 0);
    assert.equal(normalizeScore(120), 100);
    assert.equal(normalizeScore(Number.NaN), 0);
  });
});

describe('validateMagicBytes', () => {
  const pdf = Buffer.from('%PDF-1.4 rest');
  const docxHeader = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
  const doc = Buffer.from([0xd0, 0xcf, 0x11, 0xe0]);

  it('accepts a real PDF header', () => assert.equal(validateMagicBytes(pdf, 'application/pdf'), true));
  it('rejects a non-PDF claiming to be PDF', () => assert.equal(validateMagicBytes(Buffer.from('NOPE-not-pdf'), 'application/pdf'), false));
  it('accepts a DOCX ZIP local-file header', () => assert.equal(validateMagicBytes(docxHeader, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'), true));
  it('rejects a legacy .doc OLE file', () => assert.equal(validateMagicBytes(doc, 'application/msword'), false));
  it('rejects buffers shorter than 4 bytes', () => assert.equal(validateMagicBytes(Buffer.from([0x25]), 'application/pdf'), false));
});

describe('safeSecretEqual', () => {
  it('true only for equal non-empty strings', () => {
    assert.equal(safeSecretEqual('abc123', 'abc123'), true);
    assert.equal(safeSecretEqual('abc123', 'abc124'), false);
    assert.equal(safeSecretEqual('abc', 'abcd'), false); // length mismatch
  });
  it('false for missing / non-string / empty expected', () => {
    assert.equal(safeSecretEqual(undefined, 'secret'), false);
    assert.equal(safeSecretEqual(['secret'], 'secret'), false); // duplicate-header array
    assert.equal(safeSecretEqual('secret', ''), false);
    assert.equal(safeSecretEqual('secret', undefined), false);
  });
});

describe('owner test-token authorization', () => {
  it('requires both the secret and a non-empty matching IP allowlist', () => {
    assert.equal(isOwnerTestAuthorized('secret', 'secret', '203.0.113.10', new Set()), false);
    assert.equal(isOwnerTestAuthorized('wrong', 'secret', '203.0.113.10', new Set(['203.0.113.10'])), false);
    assert.equal(isOwnerTestAuthorized('secret', 'secret', '203.0.113.11', new Set(['203.0.113.10'])), false);
    assert.equal(isOwnerTestAuthorized('secret', 'secret', '::ffff:203.0.113.10', new Set(['203.0.113.10'])), true);
  });
});

describe('analysis session claims', () => {
  class FakeRedis {
    constructor() { this.values = new Map(); }
    async set(key, value, options = {}) {
      if (options.nx && this.values.has(key)) return null;
      this.values.set(key, value);
      return 'OK';
    }
    async exists(key) { return this.values.has(key) ? 1 : 0; }
    async del(key) { return this.values.delete(key) ? 1 : 0; }
  }

  it('allows only one concurrent claim for the same payment session', async () => {
    const store = new FakeRedis();
    const results = await Promise.all([
      claimAnalysis('cs_paid_123', store),
      claimAnalysis('cs_paid_123', store),
    ]);
    assert.deepEqual(results.sort(), [false, true]);
    assert.equal(await hasAnalysisClaim('cs_paid_123', store), true);
  });

  it('can release a failed attempt without changing session identity', async () => {
    const store = new FakeRedis();
    assert.equal(await claimAnalysis('cs_paid_retry', store), true);
    await releaseAnalysisClaim('cs_paid_retry', store);
    assert.equal(await claimAnalysis('cs_paid_retry', store), true);
    assert.equal(analysisClaimKey('cs_paid_retry'), 'passats:analysis:cs_paid_retry');
    assert.equal(analysisRetryKey('cs_paid_retry'), 'passats:retry:cs_paid_retry');
  });
});

describe('DOCX extraction', () => {
  it('extracts text from a real DOCX through Mammoth', async () => {
    const mammothRoot = path.resolve(path.dirname(require.resolve('mammoth')), '..');
    const fixture = path.join(mammothRoot, 'test', 'test-data', 'single-paragraph.docx');
    const text = await extractText({
      path: fixture,
      mimetype: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    });
    assert.match(text, /Walking on imported air/);
  });
});

describe('PDF extraction', () => {
  function simplePdf(text) {
    const escaped = text.replace(/([\\()])/g, '\\$1');
    const stream = `BT\n/F1 12 Tf\n72 720 Td\n(${escaped}) Tj\nET`;
    const objects = [
      '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n',
      '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n',
      '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n',
      '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n',
      `5 0 obj\n<< /Length ${Buffer.byteLength(stream)} >>\nstream\n${stream}\nendstream\nendobj\n`,
    ];
    let pdf = '%PDF-1.4\n';
    const offsets = [0];
    for (const object of objects) {
      offsets.push(Buffer.byteLength(pdf));
      pdf += object;
    }
    const xrefOffset = Buffer.byteLength(pdf);
    pdf += `xref\n0 ${objects.length + 1}\n`;
    pdf += '0000000000 65535 f \n';
    for (const offset of offsets.slice(1)) {
      pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
    }
    pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
    return Buffer.from(pdf);
  }

  it('loads the serverless worker canvas globals and extracts PDF text', async () => {
    const expected = 'Serverless PDF extraction works in production';
    const text = await extractText({
      buffer: simplePdf(expected),
      mimetype: 'application/pdf',
    });
    assert.match(text, new RegExp(expected));
    const { PDFParse } = require('pdf-parse');
    assert.match(PDFParse.setWorker(), /^data:text\/javascript;base64,/);
    assert.equal(typeof globalThis.DOMMatrix, 'function');
    assert.equal(typeof globalThis.ImageData, 'function');
    assert.equal(typeof globalThis.Path2D, 'function');
  });
});

describe('checkOrigin (CSRF)', () => {
  function fakeRes() {
    return { statusCode: null, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
  }
  it('allows a request from an allowed origin', () => {
    const res = fakeRes();
    assert.equal(checkOrigin({ headers: { origin: 'https://test.passats.example' } }, res), true);
    assert.equal(res.statusCode, null);
  });
  it('rejects a request with a foreign origin (403)', () => {
    const res = fakeRes();
    assert.equal(checkOrigin({ headers: { origin: 'https://evil.example' }, ip: '1.2.3.4', path: '/api/checkout' }, res), false);
    assert.equal(res.statusCode, 403);
  });
  it('rejects a request with no origin header (403)', () => {
    const res = fakeRes();
    assert.equal(checkOrigin({ headers: {}, ip: '1.2.3.4', path: '/api/checkout' }, res), false);
    assert.equal(res.statusCode, 403);
  });
});

describe('analyzeCv (real path, injected fake client)', () => {
  const opts = (behavior) => ({ client: fakeClient(behavior), model: 'test-model' });

  it('allows sufficient time for structured model output in a serverless request', () => {
    assert.equal(LLM_TIMEOUT_MS, 55000);
  });

  it('parses a valid response and normalizes 0-1 scores', async () => {
    const res = await analyzeCv('cv text long enough', '', opts(() => ({
      stop_reason: 'end_turn',
      content: [{ type: 'text', text: JSON.stringify(validReport()) }],
    })));
    assert.equal(res.overallScore, 72);
    assert.equal(res.metrics.keywords.score, 65);
    assert.equal(res.metrics.formatting.score, 78);
  });

  it('throws on a refusal stop_reason', async () => {
    await assert.rejects(
      analyzeCv('cv', '', opts(() => ({ stop_reason: 'refusal', stop_details: { category: 'cyber' }, content: [] }))),
      /invalid format/,
    );
  });

  it('throws when there is no text block', async () => {
    await assert.rejects(
      analyzeCv('cv', '', opts(() => ({ stop_reason: 'end_turn', content: [] }))),
      /invalid format/,
    );
  });

  it('throws on invalid JSON', async () => {
    await assert.rejects(
      analyzeCv('cv', '', opts(() => ({ stop_reason: 'end_turn', content: [{ type: 'text', text: 'not json{' }] }))),
      /invalid format/,
    );
  });

  it('maps an abort/timeout error to LLM_TIMEOUT', async () => {
    for (const name of ['APIUserAbortError', 'AbortError', 'APIConnectionTimeoutError']) {
      await assert.rejects(
        analyzeCv('cv', '', opts(() => { const e = new Error('boom'); e.name = name; throw e; })),
        /^Error: LLM_TIMEOUT$/,
      );
    }
  });

  it('re-throws a non-timeout API error unchanged', async () => {
    await assert.rejects(
      analyzeCv('cv', '', opts(() => { const e = new Error('rate limited'); e.name = 'RateLimitError'; throw e; })),
      /rate limited/,
    );
  });
});

describe('/api/test-token gating', () => {
  it('returns 404 when TEST_SECRET is unset', async () => {
    const res = await supertest(app).get('/api/test-token');
    assert.equal(res.status, 404);
  });
});
