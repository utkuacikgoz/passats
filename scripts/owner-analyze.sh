#!/usr/bin/env bash
# owner-analyze.sh — run a REAL end-to-end analysis with no payment.
#
# Uses the owner-only /api/test-token endpoint (gated by TEST_SECRET +
# TEST_ALLOWED_IPS) to mint a valid single-use token, then POSTs a CV to
# /api/analyze and prints the Claude report. Nothing is mocked — this exercises
# the live model exactly as a paying user would.
#
# Prerequisites (set in your deployment env, then redeploy):
#   TEST_SECRET       any random string — your no-pay key
#   TEST_ALLOWED_IPS  your public IP (curl ifconfig.me) — required.
# Delete TEST_SECRET when you're done to close the backdoor.
#
# Usage:
#   TEST_SECRET=xxxxx ./scripts/owner-analyze.sh path/to/resume.pdf ["optional job description"]
#
# Env overrides:
#   BASE   target origin (default https://passats.vercel.app)
set -euo pipefail

BASE="${BASE:-https://passats.vercel.app}"
CV="${1:-}"
JD="${2:-}"

if [[ -z "${TEST_SECRET:-}" ]]; then
  echo "error: TEST_SECRET is not set. Run: TEST_SECRET=<your-secret> $0 <cv-file> [job-description]" >&2
  exit 1
fi
if [[ -z "$CV" || ! -f "$CV" ]]; then
  echo "error: pass a readable CV file (PDF/DOCX, <5MB) as the first argument." >&2
  echo "usage: TEST_SECRET=<secret> $0 <cv-file> [job-description]" >&2
  exit 1
fi

# JSON pretty-printer + field extractor (python3 ships on macOS).
pp() { python3 -m json.tool; }

echo "→ requesting owner token from $BASE/api/test-token"
TOKEN="$(curl -fsS "$BASE/api/test-token" -H "x-test-secret: $TEST_SECRET" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])' 2>/dev/null || true)"

if [[ -z "$TOKEN" ]]; then
  echo "error: could not get a token. Likely causes:" >&2
  echo "  - TEST_SECRET does not match the value set in your deployment env" >&2
  echo "  - your public IP is not in TEST_ALLOWED_IPS (check: curl ifconfig.me)" >&2
  echo "  - env vars were added but the app was not redeployed" >&2
  exit 1
fi
echo "  got token ${TOKEN:0:16}… (single-use, 30-min expiry)"

echo "→ analyzing $(basename "$CV")${JD:+ (with job description)}"
curl -fsS "$BASE/api/analyze" \
  -H "Origin: $BASE" \
  -H "x-passats-token: $TOKEN" \
  -F "cv=@$CV" \
  -F "jobDescription=$JD" \
  | pp
