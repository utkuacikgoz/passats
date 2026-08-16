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

RESPONSE="$(curl -sS -w $'\n%{http_code}' "$BASE/api/test-token" -H "x-test-secret: $TEST_SECRET")" || {
  echo "error: could not reach $BASE/api/test-token." >&2
  exit 1
}
STATUS="${RESPONSE##*$'\n'}"
BODY="${RESPONSE%$'\n'*}"

if [[ "$STATUS" != "200" ]]; then
  if [[ "$STATUS" == "404" ]]; then
    echo "error: owner test access was rejected (404). Check TEST_SECRET and TEST_ALLOWED_IPS." >&2
  elif [[ "$STATUS" == "429" ]]; then
    echo "error: owner test-token rate limit reached. Wait one minute, then retry." >&2
  else
    echo "error: owner test-token endpoint returned HTTP $STATUS." >&2
  fi
  exit 1
fi

TOKEN="$(printf '%s' "$BODY" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])' 2>/dev/null || true)"
if [[ -z "$TOKEN" ]]; then
  echo "error: owner test-token endpoint returned an invalid response." >&2
  exit 1
fi

echo "Open this URL in your browser (single use, expires in 30 minutes):"
echo "$BASE/#owner_test_token=$TOKEN"
