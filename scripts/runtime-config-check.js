#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const runtime = require('../config/runtime');

const root = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const vercel = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8'));
const workflow = fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8');
const functionConfig = vercel.functions?.['server.js'];
const failures = [];

if (pkg.engines?.node !== '24.x') failures.push('package.json engines.node must be 24.x');
if (!/node-version:\s*["']?24\.x["']?/.test(workflow)) failures.push('CI must run Node 24.x');
if (!functionConfig) failures.push('vercel.json must configure functions.server.js');
if (!Number.isInteger(functionConfig?.maxDuration)) failures.push('Vercel maxDuration must be an integer number of seconds');
if ((functionConfig?.maxDuration ?? 0) < runtime.REQUIRED_FUNCTION_DURATION_SECONDS) {
  failures.push(`Vercel maxDuration must be at least ${runtime.REQUIRED_FUNCTION_DURATION_SECONDS}s`);
}
if (!Number.isInteger(functionConfig?.memory) || functionConfig.memory < 1024) {
  failures.push('Vercel function memory must be at least 1024 MB for document parsing');
}

if (failures.length) {
  console.error(failures.map(message => `runtime_config_error: ${message}`).join('\n'));
  process.exitCode = 1;
} else {
  console.log(JSON.stringify({
    status: 'runtime_config_ok',
    node: pkg.engines.node,
    functionDurationSeconds: functionConfig.maxDuration,
    memoryMb: functionConfig.memory,
    budgetMs: {
      documentParsing: runtime.DOCUMENT_PARSE_TIMEOUT_MS,
      model: runtime.LLM_TIMEOUT_MS,
      reserve: runtime.REQUEST_RESERVE_MS,
      requiredTotal: runtime.REQUIRED_FUNCTION_DURATION_SECONDS * 1000,
    },
  }));
}
