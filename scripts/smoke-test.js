#!/usr/bin/env node

const BASE_URL = process.env.PASSATS_BASE_URL || process.env.BASE_URL;
const ORIGIN = process.env.PASSATS_ORIGIN || BASE_URL;
const SESSION_ID = process.env.PASSATS_SESSION_ID || null;
const TEST_SECRET = process.env.PASSATS_TEST_SECRET || null;
const HEALTH_SECRET = process.env.PASSATS_HEALTH_SECRET || null;

if (!BASE_URL) {
  console.error('Missing PASSATS_BASE_URL or BASE_URL');
  process.exit(1);
}

function assertOk(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function makePdf(text) {
  const cvText = (text || 'Jane Doe jane@example.com 555-9876 Senior Software Engineer 7 years TypeScript React Node.js AWS Docker CI/CD SQL Git. Led team of 5. Reduced deploy time by 40 percent. REST APIs 1M requests per day.').replace(/[()\\%]/g, ' ');

  // Build each part as a Buffer so byte offsets are exact
  const parts = [];
  const offsets = {};
  const push = str => parts.push(Buffer.from(str, 'latin1'));
  const totalBytes = () => parts.reduce((s, b) => s + b.length, 0);
  const pad = n => String(n).padStart(10, '0');

  push('%PDF-1.4\n');

  offsets[1] = totalBytes();
  push('1 0 obj\n<</Type /Catalog /Pages 2 0 R>>\nendobj\n');

  offsets[2] = totalBytes();
  push('2 0 obj\n<</Type /Pages /Kids [3 0 R] /Count 1>>\nendobj\n');

  offsets[3] = totalBytes();
  push('3 0 obj\n<</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources <</Font <</F1 5 0 R>>>>>>\nendobj\n');

  offsets[4] = totalBytes();
  const stream = Buffer.from(`BT /F1 12 Tf 72 720 Td (${cvText}) Tj ET`, 'latin1');
  push(`4 0 obj\n<</Length ${stream.length}>>\nstream\n`);
  parts.push(stream);
  push('\nendstream\nendobj\n');

  offsets[5] = totalBytes();
  push('5 0 obj\n<</Type /Font /Subtype /Type1 /BaseFont /Helvetica>>\nendobj\n');

  const xrefOffset = totalBytes();
  push([
    'xref\n0 6\n',
    `0000000000 65535 f \n`,
    `${pad(offsets[1])} 00000 n \n`,
    `${pad(offsets[2])} 00000 n \n`,
    `${pad(offsets[3])} 00000 n \n`,
    `${pad(offsets[4])} 00000 n \n`,
    `${pad(offsets[5])} 00000 n \n`,
    `trailer\n<</Size 6 /Root 1 0 R>>\nstartxref\n${xrefOffset}\n%%EOF\n`,
  ].join(''));

  return Buffer.concat(parts);
}

async function getHealth() {
  if (!HEALTH_SECRET) return;
  const response = await fetch(`${BASE_URL}/api/health`, {
    headers: { 'x-health-secret': HEALTH_SECRET },
  });
  const body = await response.json().catch(() => ({}));
  assertOk(response.ok, `Health check failed: ${response.status}`);
  console.log('health:', body);
}

async function createCheckout() {
  const response = await fetch(`${BASE_URL}/api/checkout`, {
    method: 'POST',
    headers: { Origin: ORIGIN },
  });
  const body = await response.json();
  assertOk(response.ok, `Checkout failed: ${response.status} ${JSON.stringify(body)}`);
  assertOk(body.url, 'Checkout did not return a URL');
  console.log('checkout_url:', body.url);
  return body.url;
}

async function getTokenFromSession(sessionId) {
  const response = await fetch(`${BASE_URL}/api/verify-payment?session_id=${encodeURIComponent(sessionId)}`);
  const body = await response.json();
  assertOk(response.ok, `Verify failed: ${response.status} ${JSON.stringify(body)}`);
  assertOk(body.token, 'Verify did not return a token');
  return body.token;
}

async function getTokenFromTestSecret() {
  const response = await fetch(`${BASE_URL}/api/test-token`, {
    headers: { 'x-test-secret': TEST_SECRET },
  });
  const body = await response.json();
  assertOk(response.ok, `Test token failed: ${response.status} ${JSON.stringify(body)}`);
  assertOk(body.token, 'Test token did not return a token');
  return body.token;
}

async function analyze(token) {
  const form = new FormData();
  form.set('jobDescription', 'Senior Software Engineer. Must have strong TypeScript, React, Node.js, AWS, Docker, CI/CD, and REST API experience.');
  form.set('cv', new Blob([makePdf()], { type: 'application/pdf' }), 'resume.pdf');

  const response = await fetch(`${BASE_URL}/api/analyze`, {
    method: 'POST',
    headers: {
      Origin: ORIGIN,
      'x-passats-token': token,
    },
    body: form,
  });
  const body = await response.json();
  assertOk(response.ok, `Analyze failed: ${response.status} ${JSON.stringify(body)}`);
  assertOk(typeof body.overallScore === 'number', 'Analyze did not return a numeric overallScore');
  console.log('analysis_score:', body.overallScore);
  console.log('analysis_verdict:', body.verdict);
}

async function main() {
  await getHealth();
  const checkoutUrl = await createCheckout();

  let token = null;

  if (SESSION_ID) {
    token = await getTokenFromSession(SESSION_ID);
    console.log('verify_payment: ok');
  } else if (TEST_SECRET) {
    console.log('verify_payment: skipped, using /api/test-token owner bypass');
    token = await getTokenFromTestSecret();
  } else {
    console.log('next_step: complete the Stripe payment in the checkout URL, then rerun with PASSATS_SESSION_ID from the /success redirect.');
    return;
  }

  await analyze(token);
  console.log('smoke_test: ok');
}

main().catch((err) => {
  console.error('smoke_test_failed:', err.message);
  process.exit(1);
});
