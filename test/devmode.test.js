/**
 * DEV_MODE is the widest bypass in the codebase. It mocks Stripe, the model and
 * Redis at once, so an instance running with it enabled hands out unlimited free
 * analyses and treats every payment as complete.
 *
 * One line stops that reaching production: a VERCEL check that exits at boot.
 * Nothing asserted it. Every other suite does `delete process.env.VERCEL` to get
 * past it, so a regression there would have been invisible until the bill
 * arrived.
 *
 * These run the real server in a child process, because the guard's whole job is
 * to call process.exit(1) and an in-process require cannot survive that.
 *
 * Usage: node --test test/devmode.test.js
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const SERVER = path.join(ROOT, 'server.js');

// Boot server.js in a child with a chosen environment and report how it went.
function boot(env) {
  const result = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(SERVER)})`], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 20000,
    env: {
      // A deliberately minimal base: inheriting the parent's environment would
      // let a stray DEV_MODE or VERCEL from the shell decide the outcome.
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      NODE_ENV: 'test',
      ...env,
    },
  });
  return { status: result.status, out: `${result.stdout || ''}${result.stderr || ''}` };
}

const PROD_CONFIG = {
  STRIPE_SECRET_KEY: 'stub-stripe-key',
  STRIPE_WEBHOOK_SECRET: 'stub-webhook-secret',
  STRIPE_PRICE_ID: 'stub-price-id',
  ANTHROPIC_API_KEY: 'stub-anthropic-key',
  JWT_SECRET: 'a'.repeat(64),
  UPSTASH_REDIS_REST_URL: 'https://redis.test',
  UPSTASH_REDIS_REST_TOKEN: 'token',
};

describe('DEV_MODE cannot run on Vercel', () => {
  it('exits non-zero when DEV_MODE and VERCEL are both set', () => {
    // The failure this prevents: payments mocked, analyses free, and nothing in
    // the product looking any different to the person spending your API budget.
    const { status, out } = boot({ DEV_MODE: 'true', VERCEL: '1' });
    assert.notEqual(status, 0, 'the process must refuse to boot, not serve mocked payments');
    assert.match(out, /DEV_MODE=true is not allowed on Vercel/i, 'the reason must be in the logs');
  });

  it('refuses whatever else is configured alongside it', () => {
    // A full production config must not make the bypass look legitimate.
    const { status } = boot({ ...PROD_CONFIG, DEV_MODE: 'true', VERCEL: '1' });
    assert.notEqual(status, 0, 'valid production config must not excuse DEV_MODE');
  });

  it('treats any VERCEL value as production, not just "1"', () => {
    for (const value of ['1', 'true', 'production', 'preview']) {
      const { status } = boot({ DEV_MODE: 'true', VERCEL: value });
      assert.notEqual(status, 0, `VERCEL=${value} must still block DEV_MODE`);
    }
  });

  it('only treats DEV_MODE as on for the exact string "true"', () => {
    // Anything looser and a stray DEV_MODE=1 or DEV_MODE=false in a dashboard
    // would silently enable the bypass.
    for (const value of ['1', 'false', 'yes', 'TRUE', '']) {
      const { status, out } = boot({ ...PROD_CONFIG, DEV_MODE: value, VERCEL: '1' });
      assert.equal(status, 0, `DEV_MODE=${JSON.stringify(value)} must not be treated as enabled`);
      assert.doesNotMatch(out, /DEV MODE/i, `DEV_MODE=${JSON.stringify(value)} announced dev mode`);
    }
  });

  it('still boots in dev mode off Vercel, which is what the suite relies on', () => {
    const { status, out } = boot({ DEV_MODE: 'true' });
    assert.equal(status, 0, 'local dev mode must keep working');
    assert.match(out, /DEV MODE/i, 'dev mode should announce itself');
  });

  it('boots a real production config without announcing dev mode', () => {
    const { status, out } = boot({ ...PROD_CONFIG, VERCEL: '1' });
    assert.equal(status, 0);
    assert.doesNotMatch(out, /DEV MODE/i);
    assert.doesNotMatch(out, /CONFIG ERROR/i, 'a complete config must not report as incomplete');
  });
});
