#!/usr/bin/env node
'use strict';

// Asserts that the declared invocation budget actually fits inside the platform
// ceiling, and that the Node version is pinned to one number everywhere.
//
// The failure this exists to prevent is silent and expensive: if the work can
// outlast `maxDuration`, Vercel kills the invocation outside our try/catch, the
// analysis claim is never released, and a paying customer is locked out of the
// report they bought until the claim TTL expires two hours later.

const fs = require('node:fs');
const path = require('node:path');
const runtime = require('../config/runtime');

const root = path.join(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

const pkg = JSON.parse(read('package.json'));
const vercel = JSON.parse(read('vercel.json'));
const nvmrc = read('.nvmrc').trim();
const workflow = read('.github/workflows/ci.yml');

const fn = vercel.functions?.['api/index.js'];
const failures = [];

// ── Node pin ────────────────────────────────────────────────────────────────
const enginesMajor = String(pkg.engines?.node || '').match(/^(\d+)/)?.[1];
const nvmrcMajor = nvmrc.match(/^v?(\d+)/)?.[1];
if (!enginesMajor) failures.push('package.json engines.node must pin a major version');
if (!nvmrcMajor) failures.push('.nvmrc must pin a version');
if (enginesMajor && nvmrcMajor && enginesMajor !== nvmrcMajor) {
  failures.push(`engines.node (${pkg.engines.node}) and .nvmrc (${nvmrc}) disagree on the Node major`);
}
// CI must take its version from .nvmrc rather than inlining a second number.
if (!/node-version-file:\s*\.nvmrc/.test(workflow)) {
  failures.push('CI must read node-version-file: .nvmrc, not inline a version');
}

// ── Serverless budget ───────────────────────────────────────────────────────
if (!fn) {
  failures.push('vercel.json must configure functions["api/index.js"]');
} else {
  if (!Number.isInteger(fn.maxDuration)) {
    failures.push('maxDuration must be an integer number of seconds');
  } else if (fn.maxDuration !== runtime.FUNCTION_DURATION_SECONDS) {
    failures.push(
      `vercel.json maxDuration (${fn.maxDuration}s) does not match config/runtime.js ` +
      `FUNCTION_DURATION_SECONDS (${runtime.FUNCTION_DURATION_SECONDS}s)`,
    );
  }
  // The routes are served from views/, which is outside the traced import graph.
  if (!fn.includeFiles || !String(fn.includeFiles).includes('views')) {
    failures.push('functions["api/index.js"].includeFiles must bundle views/**');
  }
}

const ceilingMs = runtime.FUNCTION_DURATION_SECONDS * 1000;
if (runtime.ANALYSIS_BUDGET_MS + runtime.REQUEST_RESERVE_MS > ceilingMs) {
  failures.push(
    `analysis budget (${runtime.ANALYSIS_BUDGET_MS}ms) plus reserve ` +
    `(${runtime.REQUEST_RESERVE_MS}ms) exceeds the ${ceilingMs}ms ceiling`,
  );
}
// The phases share one deadline, so the budget only has to cover the longer of
// them. If either single ceiling alone overran the budget it could never finish.
for (const [name, value] of [
  ['DOCUMENT_PARSE_TIMEOUT_MS', runtime.DOCUMENT_PARSE_TIMEOUT_MS],
  ['LLM_TIMEOUT_MS', runtime.LLM_TIMEOUT_MS],
]) {
  if (value > runtime.ANALYSIS_BUDGET_MS) {
    failures.push(`${name} (${value}ms) exceeds the shared analysis budget (${runtime.ANALYSIS_BUDGET_MS}ms)`);
  }
}

if (failures.length) {
  console.error(failures.map(message => `runtime_config_error: ${message}`).join('\n'));
  process.exitCode = 1;
} else {
  console.log(JSON.stringify({
    status: 'runtime_config_ok',
    node: pkg.engines.node,
    nvmrc,
    functionDurationSeconds: fn.maxDuration,
    budgetMs: {
      shared: runtime.ANALYSIS_BUDGET_MS,
      documentParseCeiling: runtime.DOCUMENT_PARSE_TIMEOUT_MS,
      modelCeiling: runtime.LLM_TIMEOUT_MS,
      reserve: runtime.REQUEST_RESERVE_MS,
    },
  }, null, 2));
}
