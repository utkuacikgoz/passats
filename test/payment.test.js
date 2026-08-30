/**
 * Money-path tests — the only suite that runs the app with DEV_MODE OFF.
 *
 * Every other suite boots in dev mode, where Stripe, Redis, and Claude are all
 * mocked inside server.js itself. That leaves the code that actually runs when a
 * customer pays — the verification window, the 409 on a payment that already
 * bought an analysis, the Redis claim, the retry-then-burn ladder — with no
 * coverage at all. Here the production branches execute for real; only the three
 * SDKs at the edges are replaced, by seeding require.cache before server.js is
 * loaded.
 *
 * Usage: node --test test/payment.test.js
 */
const { describe, it, before, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

// ── Fakes ────────────────────────────────────────────────────────────────────

/** Minimal in-memory stand-in for the Upstash REST client server.js uses. */
// Instances register themselves so the suite can inspect claim state without the
// production code having to export its live Redis handle.
const redisInstances = [];

class FakeRedis {
  constructor() { this.store = new Map(); redisInstances.push(this); }
  async set(key, value, opts = {}) {
    if (opts.nx && this.store.has(key)) return null;
    this.store.set(key, String(value));
    return 'OK';
  }
  async exists(key) { return this.store.has(key) ? 1 : 0; }
  async del(key) { return this.store.delete(key) ? 1 : 0; }
  async get(key) { return this.store.has(key) ? this.store.get(key) : null; }
  async incr(key) {
    const next = Number(this.store.get(key) || 0) + 1;
    this.store.set(key, String(next));
    return next;
  }
  async decr(key) {
    const next = Number(this.store.get(key) || 0) - 1;
    this.store.set(key, String(next));
    return next;
  }
  async expire() { return 1; }
  pipeline() {
    const queued = [];
    const self = this;
    return {
      incr(key) { queued.push(() => self.incr(key)); return this; },
      expire(key, ttl) { queued.push(() => self.expire(key, ttl)); return this; },
      async exec() {
        const results = [];
        for (const run of queued) results.push(await run());
        return results;
      },
    };
  }
}

const stripeState = {
  session: null,
  updates: [],
  created: [],
  nextEvent: null,
  // Set to simulate an account or API version that will not accept custom_text.
  rejectCustomText: false,
};

class FakeStripe {
  constructor() {
    this.checkout = {
      sessions: {
        create: async params => {
          stripeState.created.push(params);
          if (stripeState.rejectCustomText && params.custom_text) {
            const err = new Error('Received unknown parameter: custom_text');
            err.type = 'StripeInvalidRequestError';
            err.statusCode = 400;
            throw err;
          }
          return { id: 'cs_test_created', url: 'https://checkout.stripe.test/cs_test_created' };
        },
        retrieve: async id => {
          if (!stripeState.session) throw new Error(`No such session: ${id}`);
          return stripeState.session;
        },
        update: async (id, params) => {
          stripeState.updates.push({ id, params });
          if (stripeState.session) {
            stripeState.session.metadata = { ...(stripeState.session.metadata || {}), ...params.metadata };
          }
          return stripeState.session;
        },
      },
    };
    this.webhooks = {
      constructEvent: () => {
        if (!stripeState.nextEvent) throw new Error('Invalid signature');
        return stripeState.nextEvent;
      },
    };
  }
}

const llmState = { calls: 0, failures: 0, response: null };

function validReport() {
  return {
    overallScore: 0.72, // deliberately 0-1 to prove normalizeScore runs on the real path
    verdict: 'Needs Work',
    verdictDetail: 'Your Skills section is missing.',
    detectedRole: 'Software Engineer',
    metrics: {
      keywords: { score: 65, note: 'No Skills section detected.' },
      formatting: { score: 78, note: 'Headings are present.' },
      readability: { score: 80, note: 'Sentences are short.' },
      contactInfo: { score: 90, note: 'Email and phone present.' },
    },
    issues: [{ severity: 'critical', title: 'No Skills section', detail: 'Add one under Experience.' }],
    keywordsFound: ['JavaScript'],
    keywordsMissing: ['CI/CD'],
    topFixes: ['Add a Skills section.'],
  };
}

class FakeAnthropic {
  constructor() {
    this.messages = {
      create: async () => {
        llmState.calls += 1;
        if (llmState.failures > 0) {
          llmState.failures -= 1;
          const err = new Error('upstream exploded');
          err.name = 'APIConnectionError';
          throw err;
        }
        return {
          stop_reason: 'end_turn',
          content: [{ type: 'text', text: JSON.stringify(llmState.response || validReport()) }],
        };
      },
    };
  }
}

function stub(moduleName, exports) {
  const resolved = require.resolve(moduleName);
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports, children: [], paths: [] };
}

// ── Boot the app in production mode ──────────────────────────────────────────

const BASE_URL = 'https://passats.test';
process.env.DEV_MODE = '';
delete process.env.VERCEL;
Object.assign(process.env, {
  BASE_URL,
  // Deliberately not shaped like real credentials: the SDKs are stubbed and
  // never parse these, and secret scanners should have nothing to match on.
  STRIPE_SECRET_KEY: 'stub-stripe-key',
  STRIPE_WEBHOOK_SECRET: 'stub-webhook-secret',
  STRIPE_PRICE_ID: 'stub-price-id',
  ANTHROPIC_API_KEY: 'stub-anthropic-key',
  JWT_SECRET: 'a'.repeat(64),
  UPSTASH_REDIS_REST_URL: 'https://redis.test',
  UPSTASH_REDIS_REST_TOKEN: 'token',
});
delete process.env.POSTHOG_API_KEY;
delete process.env.TEST_SECRET;
// Two codes: one with headroom, one single-use, so the cap can be exhausted.
// One code per test: a shared code makes these order-dependent, and a cap is
// exactly the kind of state that leaks between them.
process.env.COUPON_CODES = 'E2E-TEST,MINT-TEST,PAIR-TEST:2,SOLO-TEST,PROBE-TEST,TYPO-TEST,ORIGIN-TEST,FAIL-TEST';

stub('stripe', FakeStripe);
stub('@upstash/redis', { Redis: FakeRedis });
stub('@anthropic-ai/sdk', FakeAnthropic);

const app = require('../server');
const supertest = require('supertest');
const request = supertest(app);
const redis = () => redisInstances.at(-1);

// ── Helpers ──────────────────────────────────────────────────────────────────

function makePdf(text) {
  const content = text || 'John Doe john@example.com 555-1234 Software Engineer with 5 years experience in JavaScript, React, Node.js, SQL, Git.';
  const stream = `1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n4 0 obj<</Length ${content.length + 20}>>stream\nBT /F1 12 Tf (${content}) Tj ET\nendstream\nendobj\n5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n`;
  return Buffer.from(`%PDF-1.4\n${stream}xref\n0 6\n0000000000 65535 f \ntrailer<</Size 6/Root 1 0 R>>\nstartxref\n${stream.length}\n%%EOF`);
}

function paidSession(overrides = {}) {
  return {
    id: 'cs_test_paid',
    payment_status: 'paid',
    created: Math.floor(Date.now() / 1000) - 60,
    metadata: {},
    amount_total: 299,
    currency: 'usd',
    ...overrides,
  };
}

// A fresh client IP per test keeps the shared rate-limit buckets out of the way.
let ipCounter = 0;
const nextIp = () => `203.0.113.${(ipCounter++ % 200) + 1}`;

async function getToken(ip) {
  const res = await request
    .get(`/api/verify-payment?session_id=${stripeState.session.id}`)
    .set('x-vercel-forwarded-for', ip);
  assert.equal(res.status, 200, `expected a token, got ${res.status} ${JSON.stringify(res.body)}`);
  return res.body.token;
}

function analyze(token, ip, pdf = makePdf()) {
  return request
    .post('/api/analyze')
    .set('Origin', BASE_URL)
    .set('x-vercel-forwarded-for', ip)
    .set('x-passats-token', token)
    .attach('cv', pdf, { filename: 'cv.pdf', contentType: 'application/pdf' });
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('production boot', () => {
  it('starts fully configured — no CONFIG_ERROR, real SDK clients wired', async () => {
    const res = await request.get('/api/health').set('x-health-secret', 'nope');
    assert.equal(res.status, 404, 'health stays gated when HEALTH_SECRET is unset');
    const page = await request.get('/');
    assert.equal(page.status, 200);
  });
});

describe('verify-payment', () => {
  beforeEach(() => { stripeState.session = paidSession(); });

  it('refuses a session that has not been paid (402)', async () => {
    stripeState.session = paidSession({ payment_status: 'unpaid' });
    const res = await request.get('/api/verify-payment?session_id=cs_test_paid').set('x-vercel-forwarded-for', nextIp());
    assert.equal(res.status, 402);
  });

  it('still redeems a payment the customer comes back to later the same day', async () => {
    // The window used to be one hour from session creation. Stripe closes
    // payment at +30 minutes, so someone who paid late had barely half an hour
    // to return before being told to purchase again, after paying.
    stripeState.session = paidSession({ id: 'cs_late', metadata: {}, created: Math.floor(Date.now() / 1000) - 8 * 3600 });
    const res = await request.get('/api/verify-payment?session_id=cs_late').set('x-vercel-forwarded-for', nextIp());
    assert.equal(res.status, 200, 'eight hours later is a normal customer, not an attacker');
    assert.ok(res.body.token);
  });

  it('refuses a payment past the window without telling them to pay twice', async () => {
    stripeState.session = paidSession({ id: 'cs_ancient', metadata: {}, created: Math.floor(Date.now() / 1000) - 48 * 3600 });
    const res = await request.get('/api/verify-payment?session_id=cs_ancient').set('x-vercel-forwarded-for', nextIp());
    assert.equal(res.status, 410);
    // They paid. The money is real and no analysis was ever claimed, so the
    // copy must route them to a human, never back to the checkout button.
    assert.doesNotMatch(res.body.error, /purchase again|buy again/i);
    assert.match(res.body.error, new RegExp(app.__test.SUPPORT_EMAIL.replace(/\./g, '\\.')));
    assert.match(res.body.error, /reference [0-9a-f-]{36}/i);
  });

  it('issues a token for a fresh paid session and persists it to Stripe metadata', async () => {
    const res = await request.get('/api/verify-payment?session_id=cs_test_paid').set('x-vercel-forwarded-for', nextIp());
    assert.equal(res.status, 200);
    assert.ok(res.body.token);
    assert.ok(stripeState.updates.some(u => u.params.metadata.passats_token), 'token written back to Stripe');
  });

  it('refuses to re-issue once that payment has bought its analysis (409)', async () => {
    stripeState.session = paidSession({ id: 'cs_claimed' });
    await app.__test.claimAnalysis('cs_claimed', redis());
    const res = await request.get('/api/verify-payment?session_id=cs_claimed').set('x-vercel-forwarded-for', nextIp());
    assert.equal(res.status, 409);
    assert.match(res.body.error, /already been used/i);
  });
});

describe('analyze — the real path', () => {
  beforeEach(() => {
    llmState.calls = 0;
    llmState.failures = 0;
    llmState.response = null;
    redis().store.clear();
  });

  it('scores a CV, normalises a 0-1 score to 0-100, and burns the payment', async () => {
    stripeState.session = paidSession({ id: 'cs_happy', metadata: {} });
    const ip = nextIp();
    const token = await getToken(ip);

    const res = await analyze(token, ip);
    assert.equal(res.status, 200);
    assert.equal(res.body.overallScore, 72, 'normalizeScore ran on the production path');
    assert.equal(res.body.verdict, 'Needs Work');
    assert.equal(llmState.calls, 1);
    assert.equal(await app.__test.hasAnalysisClaim('cs_happy', redis()), true);
  });

  it('blocks a second analysis on the same payment, even with a second valid token', async () => {
    stripeState.session = paidSession({ id: 'cs_replay', metadata: {} });
    const ip = nextIp();
    const first = await getToken(ip);
    assert.equal((await analyze(first, ip)).status, 200);

    // A different JWT for the same payment must lose to the existing claim.
    const jwt = require('jsonwebtoken');
    const crypto = require('crypto');
    const second = jwt.sign({ sessionId: 'cs_replay', jti: crypto.randomUUID() }, process.env.JWT_SECRET, { expiresIn: '30m' });
    const res = await analyze(second, ip);
    assert.equal(res.status, 403);
    assert.match(res.body.error, /already used/i);
  });

  it('releases the claim on a retryable failure so the customer can try again', async () => {
    stripeState.session = paidSession({ id: 'cs_retry', metadata: {} });
    const ip = nextIp();
    const token = await getToken(ip);

    llmState.failures = 1;
    const failed = await analyze(token, ip);
    assert.equal(failed.status, 500);
    assert.match(failed.body.error, /try again shortly/i);
    assert.equal(await app.__test.hasAnalysisClaim('cs_retry', redis()), false, 'claim released');

    const retried = await analyze(token, ip);
    assert.equal(retried.status, 200, 'the same token still works after a retryable failure');
  });

  it('burns the payment after three failures and hands over a support reference', async () => {
    stripeState.session = paidSession({ id: 'cs_burn', metadata: {} });
    const ip = nextIp();
    const token = await getToken(ip);

    llmState.failures = 5;
    for (let attempt = 1; attempt <= 3; attempt++) {
      const res = await analyze(token, ip);
      assert.equal(res.status, 500);
      assert.match(res.body.error, /try again shortly/i, `attempt ${attempt} stays retryable`);
    }

    const exhausted = await analyze(token, ip);
    assert.equal(exhausted.status, 500);
    assert.match(exhausted.body.error, new RegExp(app.__test.SUPPORT_EMAIL.replace('.', '\\.')));
    assert.match(exhausted.body.error, /reference [0-9a-f-]{36}/i, 'quotes a request id support can search for');
  });

  it('does not burn the payment when the retry counter itself is unreadable', async () => {
    stripeState.session = paidSession({ id: 'cs_redis_blip', metadata: {} });
    const ip = nextIp();
    const token = await getToken(ip);

    // A transient Upstash fault on the retry counter used to resolve to 999,
    // which read as "retries exhausted" and consumed a paid analysis over an
    // outage the customer had no part in. Fail open instead.
    const store = redis();
    const realIncr = store.incr.bind(store);
    store.incr = async key => {
      if (key === app.__test.analysisRetryKey('cs_redis_blip')) throw new Error('upstash unavailable');
      return realIncr(key);
    };

    llmState.failures = 1;
    let failed;
    try {
      failed = await analyze(token, ip);
    } finally {
      store.incr = realIncr;
    }

    assert.equal(failed.status, 500);
    assert.match(failed.body.error, /try again shortly/i, 'stays retryable, does not hand over a support reference');
    assert.equal(await app.__test.hasAnalysisClaim('cs_redis_blip', store), false, 'claim released despite the counter failing');

    const retried = await analyze(token, ip);
    assert.equal(retried.status, 200, 'the customer still gets the analysis they paid for');
  });

  it('does not burn the payment when the document has too little text', async () => {
    stripeState.session = paidSession({ id: 'cs_thin', metadata: {} });
    const ip = nextIp();
    const token = await getToken(ip);

    const res = await analyze(token, ip, makePdf('Jane'));
    assert.equal(res.status, 422);
    assert.equal(await app.__test.hasAnalysisClaim('cs_thin', redis()), false, 'claim released — user mistake, not abuse');
    assert.equal(llmState.calls, 0, 'no model spend on an unreadable file');
  });

  it('rejects a cross-origin analyze request', async () => {
    stripeState.session = paidSession({ id: 'cs_csrf', metadata: {} });
    const ip = nextIp();
    const token = await getToken(ip);
    const res = await request
      .post('/api/analyze')
      .set('Origin', 'https://evil.example')
      .set('x-vercel-forwarded-for', ip)
      .set('x-passats-token', token)
      .attach('cv', makePdf(), { filename: 'cv.pdf', contentType: 'application/pdf' });
    assert.equal(res.status, 403);
  });

  it('reports the Ads conversion only for a payment Stripe confirms', async () => {
    // The purchase completes on checkout.stripe.com, where Stripe's CSP does not
    // allow Google tags, so the conversion is reported on the return leg. That
    // makes it worth pinning that it rides on real verification: reaching
    // /success proves nothing on its own, anyone can type that URL.
    const { adsConversionFor } = app.__test;
    assert.equal(adsConversionFor(paidSession()), undefined, 'no conversion action configured means none is reported');

    process.env.GOOGLE_ADS_CONVERSION_SEND_TO = 'AW-1234567890/abcDEF_ghi';
    try {
      const usd = adsConversionFor(paidSession());
      assert.equal(usd.sendTo, 'AW-1234567890/abcDEF_ghi');
      assert.equal(usd.value, 2.99, 'Stripe reports minor units; Ads wants the major unit');
      assert.equal(usd.currency, 'USD');
      assert.equal(usd.transactionId, 'cs_test_paid', 'without this Google cannot discard a duplicate');

      // Checkout prices in the buyer's currency. A hardcoded 2.99 USD would
      // misreport every non-USD sale, which is how ad spend gets misjudged.
      const lira = adsConversionFor(paidSession({ amount_total: 15000, currency: 'try' }));
      assert.equal(lira.value, 150);
      assert.equal(lira.currency, 'TRY');
    } finally {
      delete process.env.GOOGLE_ADS_CONVERSION_SEND_TO;
    }
  });

  it('rejects a cross-origin parse preview', async () => {
    // The free endpoint takes no token, so the origin check is the only thing
    // stopping another site from posting its visitors' files through it.
    const res = await request
      .post('/api/parse-preview')
      .set('Origin', 'https://evil.example')
      .set('x-vercel-forwarded-for', nextIp())
      .attach('cv', makePdf(), { filename: 'cv.pdf', contentType: 'application/pdf' });
    assert.equal(res.status, 403);
  });
});

describe('coupon redemption', () => {
  const jwt = require('jsonwebtoken');
  const redeem = (code, ip) => request
    .post('/api/redeem-coupon')
    .set('origin', BASE_URL)
    .set('x-vercel-forwarded-for', ip)
    .send({ code });

  it('mints a working upload token and spends one redemption', async () => {
    const res = await redeem('MINT-TEST', nextIp());
    assert.equal(res.status, 200);
    const payload = jwt.verify(res.body.token, process.env.JWT_SECRET);
    assert.match(payload.sessionId, /^coupon_/, 'coupon sessions are their own namespace');
    assert.equal(await redis().get(app.__test.couponKey('MINT-TEST')), '1');
  });

  it('gives every redemption its own analysis rather than sharing one claim', async () => {
    // The whole design rests on this: a per-redemption sessionId means the
    // existing Redis claim grants one analysis each, with no coupon-specific
    // replay logic anywhere downstream.
    const first = await redeem('PAIR-TEST', nextIp());
    const second = await redeem('PAIR-TEST', nextIp());
    assert.equal(first.status, 200);
    assert.equal(second.status, 200);
    const a = jwt.verify(first.body.token, process.env.JWT_SECRET).sessionId;
    const b = jwt.verify(second.body.token, process.env.JWT_SECRET).sessionId;
    assert.notEqual(a, b);
    assert.equal(app.__test.analysisSource(a), 'coupon', 'free analyses stay separable from sold ones');
  });

  it('stops at the configured cap', async () => {
    assert.equal((await redeem('SOLO-TEST', nextIp())).status, 200);
    const second = await redeem('SOLO-TEST', nextIp());
    assert.equal(second.status, 404, 'a spent code must not mint a second token');
    // The tally stays honest: the rejected attempt is decremented back.
    assert.equal(await redis().get(app.__test.couponKey('SOLO-TEST')), '1');
  });

  it('answers a spent code and an unknown code identically', async () => {
    assert.equal((await redeem('PROBE-TEST', nextIp())).status, 200);
    const spent = await redeem('PROBE-TEST', nextIp());
    const unknown = await redeem('NO-SUCH-CODE', nextIp());
    assert.equal(spent.status, unknown.status);
    assert.deepEqual(spent.body, unknown.body, 'a probe must not learn that a code exists');
  });

  it('accepts the code as a person would type it', async () => {
    const res = await redeem('  typo-test  ', nextIp());
    assert.equal(res.status, 200, 'case and spacing are typos, not a security boundary');
  });

  it('refuses cross-origin redemption', async () => {
    const res = await request
      .post('/api/redeem-coupon')
      .set('origin', 'https://evil.test')
      .set('x-vercel-forwarded-for', nextIp())
      .send({ code: 'ORIGIN-TEST' });
    assert.equal(res.status, 403);
    assert.equal(await redis().get(app.__test.couponKey('ORIGIN-TEST')), null, 'a refused request must not spend the code');
  });

  it('rate limits guessing from one address', async () => {
    const ip = nextIp();
    const results = [];
    for (const code of ['A', 'B', 'C', 'D', 'E', 'F', 'G']) results.push((await redeem(code, ip)).status);
    assert.ok(results.includes(429), `expected a 429 among ${results.join(',')}`);
  });

  it('denies rather than grants when the counter is unreachable', async () => {
    // The opposite call from the analysis retry counter, and deliberately so:
    // that one fails open to protect a customer who already paid, this one
    // fails closed because it hands out product for free.
    const store = redis();
    const realIncr = store.incr.bind(store);
    store.incr = async key => {
      if (key === app.__test.couponKey('FAIL-TEST')) throw new Error('upstash unavailable');
      return realIncr(key);
    };
    let res;
    try {
      res = await redeem('FAIL-TEST', nextIp());
    } finally {
      store.incr = realIncr;
    }
    assert.equal(res.status, 503);
    assert.doesNotMatch(JSON.stringify(res.body), /token/i, 'no token may escape on the failure path');
  });

  it('runs a real analysis and then behaves exactly like a spent payment', async () => {
    // End to end through the production path: the coupon token must buy one
    // analysis and then hit the same claim that stops a paid token replaying.
    const ip = nextIp();
    const redeemed = await redeem('E2E-TEST', ip);
    assert.equal(redeemed.status, 200);
    const token = redeemed.body.token;
    const sessionId = jwt.verify(token, process.env.JWT_SECRET).sessionId;

    const first = await analyze(token, ip);
    assert.equal(first.status, 200, `expected a report, got ${JSON.stringify(first.body)}`);
    assert.ok(Number.isInteger(first.body.overallScore));
    assert.equal(await app.__test.hasAnalysisClaim(sessionId, redis()), true, 'the analysis is claimed');

    const replay = await analyze(token, ip);
    assert.equal(replay.status, 403, 'a coupon token is single-use, same as a payment');
  });

  it('never puts the live code in the Redis key', () => {
    assert.doesNotMatch(app.__test.couponKey('MINT-TEST'), /MINT-TEST/);
  });
});

describe('checkout', () => {
  beforeEach(() => {
    stripeState.rejectCustomText = false;
    stripeState.created.length = 0;
  });

  it('states the withdrawal-right waiver at the point of payment', async () => {
    const res = await request.post('/api/checkout').set('Origin', BASE_URL).set('x-vercel-forwarded-for', nextIp());
    assert.equal(res.status, 200);
    const params = stripeState.created.at(-1);
    const message = params.custom_text.submit.message;
    assert.match(message, /immediately/i);
    assert.match(message, /right of withdrawal/i);
    assert.match(message, new RegExp(app.__test.SUPPORT_EMAIL.replace('.', '\\.')));
  });

  it('still sells the analysis if Stripe rejects the consent copy', async () => {
    // A rejected optional field must never take the funnel down.
    stripeState.rejectCustomText = true;
    const res = await request.post('/api/checkout').set('Origin', BASE_URL).set('x-vercel-forwarded-for', nextIp());

    assert.equal(res.status, 200);
    assert.ok(res.body.url, 'the customer still gets a checkout URL');
    assert.equal(stripeState.created.length, 2, 'retried once, without custom_text');
    assert.equal(stripeState.created[1].custom_text, undefined);
  });

  it('does not retry a genuine Stripe outage', async () => {
    const original = app.__test.isInvalidRequest;
    assert.equal(original({ type: 'StripeInvalidRequestError' }), true);
    assert.equal(original({ statusCode: 400 }), true);
    assert.equal(original({ type: 'StripeAPIError', statusCode: 503 }), false);
    assert.equal(original(new Error('socket hang up')), false);
  });
});

describe('webhook', () => {
  it('is idempotent against a replayed event, using the live session rather than the payload snapshot', async () => {
    // Stripe replays the ORIGINAL payload, so the snapshot never carries our token.
    stripeState.session = paidSession({ id: 'cs_hook', metadata: {} });
    const snapshot = { type: 'checkout.session.completed', data: { object: { id: 'cs_hook', metadata: {} } } };
    stripeState.nextEvent = snapshot;

    const before = stripeState.updates.length;
    let res = await request.post('/api/webhook').set('stripe-signature', 'sig').send(Buffer.from('{}'));
    assert.equal(res.status, 200);
    assert.equal(stripeState.updates.length, before + 1, 'first delivery mints a token');

    stripeState.nextEvent = snapshot; // same payload, as Stripe would retry it
    res = await request.post('/api/webhook').set('stripe-signature', 'sig').send(Buffer.from('{}'));
    assert.equal(res.status, 200);
    assert.equal(stripeState.updates.length, before + 1, 'replay is a no-op');
  });

  it('rejects an unsigned webhook', async () => {
    stripeState.nextEvent = null;
    const res = await request.post('/api/webhook').set('stripe-signature', 'bad').send(Buffer.from('{}'));
    assert.equal(res.status, 400);
  });
});

describe('rate limiting keys on the header the edge controls', () => {
  before(() => { stripeState.session = paidSession(); });

  it('prefers x-vercel-forwarded-for over a client-supplied x-forwarded-for', () => {
    const spoofed = {
      headers: { 'x-vercel-forwarded-for': '198.51.100.7', 'x-forwarded-for': '203.0.113.1' },
      ip: '203.0.113.1',
    };
    assert.equal(app.__test.clientIp(spoofed), '198.51.100.7');
  });

  it('falls back to req.ip when the edge header is absent', () => {
    assert.equal(app.__test.clientIp({ headers: {}, ip: '::ffff:198.51.100.9' }), '198.51.100.9');
  });

  it('buckets redis keys by window so a missed EXPIRE cannot block forever', async () => {
    const store = redis();
    store.store.clear();
    const ip = nextIp();
    await request.post('/api/checkout').set('Origin', BASE_URL).set('x-vercel-forwarded-for', ip);
    const keys = [...store.store.keys()].filter(k => k.includes('ratelimit'));
    assert.ok(keys.length > 0, 'a rate-limit key was written');
    assert.match(keys[0], /:\d+$/, 'key carries a time bucket suffix');
  });
});
