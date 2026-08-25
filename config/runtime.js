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
const DOCUMENT_PARSE_TIMEOUT_MS = 15_000;
// Hard ceiling on the model call, applied only when the parse left room for it.
const LLM_TIMEOUT_MS = 55_000;
// Left for request parsing, the upload write, Redis round trips, the JSON
// response and PostHog's bounded flush.
const REQUEST_RESERVE_MS = 5_000;

// What the two phases may consume between them.
const ANALYSIS_BUDGET_MS = FUNCTION_DURATION_SECONDS * 1000 - REQUEST_RESERVE_MS;

module.exports = {
  FUNCTION_DURATION_SECONDS,
  DOCUMENT_PARSE_TIMEOUT_MS,
  LLM_TIMEOUT_MS,
  REQUEST_RESERVE_MS,
  ANALYSIS_BUDGET_MS,
};
