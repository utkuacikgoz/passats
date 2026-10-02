'use strict';

// The serverless invocation budget, in one place.
//
// A Vercel invocation is killed at `functions["api/index.js"].maxDuration` in
// vercel.json. That kill happens outside our try/catch, so the analysis claim is
// never released and a paying customer is locked out of the analysis they bought
// for the full two-hour claim TTL. The budget below therefore has to be provably
// smaller than that ceiling, and `npm run runtime:check` asserts exactly that.
//
// The phases share one deadline rather than each holding its own timeout: a slow
// parse now eats into the model's allowance instead of adding to it. Summing the
// two independently would need 15s + 55s + reserve, which overruns a 60s ceiling.
const FUNCTION_DURATION_SECONDS = 60;

// Hard ceiling on document parsing. A file that needs longer is pathological.
// This covers the whole document phase, text extraction and the hidden-text scan
// together, so adding the scan did not widen the budget.
const DOCUMENT_PARSE_TIMEOUT_MS = 15_000;
// The hidden-text scan's own slice of the document phase. It reads the file a
// second time through pdfjs's operator list, and it is worth nothing if it costs
// someone their analysis, so it is capped and it is skipped when the parse has
// already spent the phase.
const HIDDEN_TEXT_TIMEOUT_MS = 5_000;
// Below this there is no point starting: the scan would be killed mid-page and
// the text would go to the model unexamined either way.
const HIDDEN_TEXT_MIN_BUDGET_MS = 1_500;
// Hard ceiling on the model call, applied only when the parse left room for it.
const LLM_TIMEOUT_MS = 55_000;
// Left for request parsing, the upload write, Redis round trips, the JSON
// response and PostHog's bounded flush.
const REQUEST_RESERVE_MS = 5_000;
// Owner alerts are sent from inside that reserve, after the claim is released,
// so a slow webhook can never cost a customer their analysis. runtime:check
// asserts this stays smaller than the reserve.
const ALERT_TIMEOUT_MS = 2_500;
// PostHog's bounded flush, which also runs inside the reserve. On the failure
// paths it runs concurrently with an alert, so the reserve pays for the slower
// of the two, not their sum.
const POSTHOG_FLUSH_TIMEOUT_MS = 2_000;
// What the reserve must still hold after that: Redis round trips in the catch
// block, the JSON response and upload cleanup.
const RESERVE_TAIL_MS = 1_000;

// What the two phases may consume between them.
const ANALYSIS_BUDGET_MS = FUNCTION_DURATION_SECONDS * 1000 - REQUEST_RESERVE_MS;

module.exports = {
  FUNCTION_DURATION_SECONDS,
  DOCUMENT_PARSE_TIMEOUT_MS,
  HIDDEN_TEXT_TIMEOUT_MS,
  HIDDEN_TEXT_MIN_BUDGET_MS,
  LLM_TIMEOUT_MS,
  REQUEST_RESERVE_MS,
  ALERT_TIMEOUT_MS,
  POSTHOG_FLUSH_TIMEOUT_MS,
  RESERVE_TAIL_MS,
  ANALYSIS_BUDGET_MS,
};
