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
const { analyzeCv, sanitizeSchema, normalizeScore, validateMagicBytes, checkOrigin, safeSecretEqual, ATS_OUTPUT_SCHEMA } = app.__test;

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
});

describe('validateMagicBytes', () => {
  const pdf = Buffer.from('%PDF-1.4 rest');
  const docxHeader = (() => { const b = Buffer.alloc(64); b[0] = 0x50; b[1] = 0x4b; b.write('word/', 30); return b; })();
  const zipNoWord = (() => { const b = Buffer.alloc(64); b[0] = 0x50; b[1] = 0x4b; return b; })();
  const doc = Buffer.from([0xd0, 0xcf, 0x11, 0xe0]);

  it('accepts a real PDF header', () => assert.equal(validateMagicBytes(pdf, 'application/pdf'), true));
  it('rejects a non-PDF claiming to be PDF', () => assert.equal(validateMagicBytes(Buffer.from('NOPE-not-pdf'), 'application/pdf'), false));
  it('accepts a DOCX (PK + word/ marker)', () => assert.equal(validateMagicBytes(docxHeader, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'), true));
  it('rejects a PK zip with no word/ marker as DOCX', () => assert.equal(validateMagicBytes(zipNoWord, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'), false));
  it('accepts a legacy .doc OLE header', () => assert.equal(validateMagicBytes(doc, 'application/msword'), true));
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
