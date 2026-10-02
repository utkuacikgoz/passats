'use strict';

// Owner alerts. The payment suite covers when they fire; this covers what goes
// out, and that a broken destination can never throw into a failing request.

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const alerts = require('../lib/alerts');
const { ALERT_TIMEOUT_MS, REQUEST_RESERVE_MS } = require('../config/runtime');

const ok = async () => ({ ok: true, status: 200 });

describe('owner alert payloads', () => {
  it('sends Slack its {text} field', () => {
    const { headers, payload } = alerts.formatFor('https://hooks.slack.com/services/T/B/x', 'Title', 'Body');
    assert.equal(headers['Content-Type'], 'application/json');
    assert.deepEqual(JSON.parse(payload), { text: 'Title\n\nBody' });
  });

  it('sends Discord its {content} field, inside its length limit', () => {
    const { payload } = alerts.formatFor('https://discord.com/api/webhooks/1/x', 'Title', 'x'.repeat(5000));
    const body = JSON.parse(payload);
    assert.ok(body.content.startsWith('Title'));
    assert.ok(body.content.length <= 2000);
  });

  it('sends everything else plain text, with ntfy headers that are ASCII', () => {
    const { headers, payload } = alerts.formatFor('https://ntfy.sh/some-topic', 'PassATS — down', 'Body');
    assert.equal(payload, 'Body');
    assert.equal(headers.Priority, 'urgent');
    assert.match(headers.Title, /^[\x20-\x7e]+$/);
  });
});

describe('notifyOwner', () => {
  beforeEach(() => alerts._resetForTests());

  it('does nothing without a configured URL', async () => {
    let calls = 0;
    const status = await alerts.notifyOwner({ kind: 'k1', title: 't', body: 'b', url: '', fetchImpl: async () => { calls++; return ok(); } });
    assert.equal(status, 'unconfigured');
    assert.equal(calls, 0);
  });

  it('sends once per kind per window, coordinated through Redis', async () => {
    const store = new Map();
    const redis = { set: async (key, value, opts) => (opts.nx && store.has(key) ? null : (store.set(key, value), 'OK')) };
    let calls = 0;
    const send = () => alerts.notifyOwner({ kind: 'k2', title: 't', body: 'b', url: 'https://ntfy.test/x', redis, fetchImpl: async () => { calls++; return ok(); } });
    assert.equal(await send(), 'sent');
    // Another warm instance shares Redis but not this process's memory.
    alerts._resetForTests();
    assert.equal(await send(), 'throttled');
    assert.equal(calls, 1);
    assert.ok(store.has(alerts.alertKey('k2')));
  });

  it('sends anyway when Redis is unreachable, then throttles in process', async () => {
    const redis = { set: async () => { throw new Error('upstash down'); } };
    let calls = 0;
    const send = () => alerts.notifyOwner({ kind: 'k3', title: 't', body: 'b', url: 'https://ntfy.test/x', redis, fetchImpl: async () => { calls++; return ok(); } });
    assert.equal(await send(), 'sent');
    assert.equal(await send(), 'throttled');
    assert.equal(calls, 1);
  });

  it('never rejects: network errors, bad statuses and timeouts become a status', async () => {
    const base = { title: 't', body: 'b', url: 'https://ntfy.test/x' };
    assert.equal(await alerts.notifyOwner({ ...base, kind: 'k4', fetchImpl: async () => { throw new TypeError('fetch failed'); } }), 'failed_network');
    assert.equal(await alerts.notifyOwner({ ...base, kind: 'k5', fetchImpl: async () => ({ ok: false, status: 403 }) }), 'failed_403');
    const hang = (_url, { signal }) => new Promise((_, reject) => {
      signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
    });
    const started = Date.now();
    assert.equal(await alerts.notifyOwner({ ...base, kind: 'k6', fetchImpl: hang }), 'timeout');
    assert.ok(Date.now() - started < ALERT_TIMEOUT_MS + 500);
  });

  it('is bounded inside the serverless reserve', () => {
    assert.ok(ALERT_TIMEOUT_MS < REQUEST_RESERVE_MS);
  });
});
