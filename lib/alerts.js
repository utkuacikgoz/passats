'use strict';

// Owner alerts: the one place this service tells a human that something is wrong.
//
// Without it, an exhausted Anthropic credit balance was discovered by a customer:
// they paid, the analysis failed, and the only record was a log line nobody was
// reading. These alerts go to a single webhook the owner chooses, so the first
// failed report reaches a phone rather than a log.
//
// Three properties matter more than delivery:
//
//   It never throws. An alert is sent from inside a request that is already
//   failing, and a broken alert must not turn a recoverable failure into a crash.
//
//   It is bounded. It runs inside the serverless reserve, after the claim has
//   already been released, under a hard timeout (ALERT_TIMEOUT_MS) that
//   runtime:check asserts fits inside that reserve.
//
//   It does not page you forty times for one outage. Each kind of alert is sent
//   at most once per ALERT_THROTTLE_SECONDS, coordinated through Redis so every
//   serverless instance agrees. If Redis cannot be reached the alert is sent
//   anyway: a duplicate costs a notification, silence costs a customer.
//
// Nothing customer-identifying goes out: no résumé text, no file name, no email,
// no payment session id. The request id is included because it is what support
// searches the logs by.

const { ALERT_TIMEOUT_MS } = require('../config/runtime');

const ALERT_THROTTLE_SECONDS = 30 * 60;
const alertKey = kind => `passats:alert:${kind}`;

// In-process backstop for when Redis is unavailable, so one warm instance still
// throttles itself.
const lastSentInProcess = new Map();

/**
 * Shape the payload for the destination. Slack and Discord each reject the
 * other's field, so the host decides; anything else gets plain text, which is
 * what ntfy.sh and most generic receivers accept. ntfy reads Title, Priority and
 * Tags from headers and other receivers ignore them.
 */
function formatFor(url, title, body) {
  const host = (() => { try { return new URL(url).hostname; } catch { return ''; } })();
  const text = `${title}\n\n${body}`;
  if (host === 'hooks.slack.com') {
    return { headers: { 'Content-Type': 'application/json' }, payload: JSON.stringify({ text }) };
  }
  if (host === 'discord.com' || host === 'discordapp.com') {
    return { headers: { 'Content-Type': 'application/json' }, payload: JSON.stringify({ content: text.slice(0, 1900) }) };
  }
  return {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      // Headers must be ASCII; the title is ours, but strip anything else anyway.
      Title: title.replace(/[^\x20-\x7e]/g, ''),
      Priority: 'urgent',
      Tags: 'rotating_light',
    },
    payload: body,
  };
}

/**
 * Claim the right to send this kind of alert now. Returns true when this call
 * should send. Fails open: an unreachable Redis means send.
 */
async function claimSendWindow(kind, redis, now) {
  const last = lastSentInProcess.get(kind);
  if (last && now - last < ALERT_THROTTLE_SECONDS * 1000) return false;
  if (!redis) return true;
  try {
    const won = await redis.set(alertKey(kind), String(now), { nx: true, ex: ALERT_THROTTLE_SECONDS });
    return won !== null;
  } catch {
    return true;
  }
}

/**
 * Send one owner alert. Resolves to a short status string for logging and never
 * rejects.
 *
 * @param {object} options
 * @param {string} options.kind      Throttle key: one alert per kind per window.
 * @param {string} options.title     One line, ASCII-safe.
 * @param {string} options.body      What happened and what to do.
 * @param {object} [options.redis]   Shared throttle store.
 * @param {string} [options.url]     Defaults to process.env.ALERT_WEBHOOK_URL.
 * @param {Function} [options.fetchImpl]
 */
async function notifyOwner({ kind, title, body, redis, url = process.env.ALERT_WEBHOOK_URL, fetchImpl = fetch }) {
  if (!url) return 'unconfigured';
  const now = Date.now();
  if (!await claimSendWindow(kind, redis, now)) return 'throttled';
  lastSentInProcess.set(kind, now);

  const { headers, payload } = formatFor(url, title, body);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ALERT_TIMEOUT_MS);
  try {
    const res = await fetchImpl(url, { method: 'POST', headers, body: payload, signal: controller.signal });
    return res.ok ? 'sent' : `failed_${res.status}`;
  } catch (err) {
    return err?.name === 'AbortError' ? 'timeout' : 'failed_network';
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { notifyOwner, formatFor, ALERT_THROTTLE_SECONDS, alertKey, _resetForTests: () => lastSentInProcess.clear() };
