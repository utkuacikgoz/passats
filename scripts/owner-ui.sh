#!/usr/bin/env bash
# owner-ui.sh — print a one-time, no-payment URL for testing the real UI.
# Requires the same TEST_SECRET + TEST_ALLOWED_IPS production gate as
# owner-analyze.sh. The signed token expires after 30 minutes and the URL
# fragment is stripped by the page before it displays the upload form.
set -euo pipefail

BASE="${BASE:-https://passats.vercel.app}"

if [[ -z "${TEST_SECRET:-}" ]]; then
  echo "error: TEST_SECRET is not set." >&2
  exit 1
fi

TOKEN="$(curl -fsS "$BASE/api/test-token" -H "x-test-secret: $TEST_SECRET" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])' 2>/dev/null || true)"

if [[ -z "$TOKEN" ]]; then
  echo "error: could not get an owner test token. Check TEST_SECRET, TEST_ALLOWED_IPS, and the production deployment." >&2
  exit 1
fi

echo "Open this URL in your browser (single use, expires in 30 minutes):"
echo "$BASE/#owner_test_token=$TOKEN"
