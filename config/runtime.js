'use strict';

// Keep these below the platform limit in vercel.json. The runtime check in CI
// prevents either side of this contract from drifting unnoticed.
const DOCUMENT_PARSE_TIMEOUT_MS = 15_000;
const LLM_TIMEOUT_MS = 55_000;
const REQUEST_RESERVE_MS = 30_000;
const REQUIRED_FUNCTION_DURATION_SECONDS = Math.ceil(
  (DOCUMENT_PARSE_TIMEOUT_MS + LLM_TIMEOUT_MS + REQUEST_RESERVE_MS) / 1000,
);

module.exports = {
  DOCUMENT_PARSE_TIMEOUT_MS,
  LLM_TIMEOUT_MS,
  REQUEST_RESERVE_MS,
  REQUIRED_FUNCTION_DURATION_SECONDS,
};
