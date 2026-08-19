#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const DEFAULT_FIXTURE = path.join(__dirname, '..', 'test', 'fixtures', 'ats-golden-set.json');
const ROLE_FAMILIES = [
  'software-engineering',
  'product-management',
  'data',
  'marketing-sales',
  'finance-operations',
  'edge-cases',
];

const normalizeTerm = value => String(value).trim().toLocaleLowerCase('en-US');

function validateBenchmark(benchmark) {
  const errors = [];
  if (benchmark?.version !== 1) errors.push('benchmark.version must be 1');
  if (!Array.isArray(benchmark?.cases)) return [...errors, 'benchmark.cases must be an array'];
  if (benchmark.cases.length < 60) errors.push('benchmark must contain at least 60 cases');

  const ids = new Set();
  const familyCounts = Object.fromEntries(ROLE_FAMILIES.map(family => [family, 0]));
  for (const [index, item] of benchmark.cases.entries()) {
    const at = `cases[${index}]`;
    if (!item?.id || ids.has(item.id)) errors.push(`${at}.id must be present and unique`);
    ids.add(item?.id);
    if (!(item?.roleFamily in familyCounts)) errors.push(`${at}.roleFamily is not recognized`);
    else familyCounts[item.roleFamily]++;
    if (typeof item?.resumeText !== 'string' || item.resumeText.length < 100) errors.push(`${at}.resumeText is too short`);
    if (typeof item?.jobDescription !== 'string' || item.jobDescription.length < 30) errors.push(`${at}.jobDescription is too short`);
    for (const field of ['presentRequirements', 'missingRequirements', 'mustNotInvent']) {
      if (!Array.isArray(item?.expected?.[field]) || item.expected[field].length === 0) {
        errors.push(`${at}.expected.${field} must be a non-empty array`);
      }
    }
  }
  for (const family of ROLE_FAMILIES) {
    if (familyCounts[family] < 10) errors.push(`${family} must contain at least 10 cases`);
  }
  return errors;
}

function scoreResult(item, result) {
  const predictedMissing = new Set((result.keywordsMissing || []).map(normalizeTerm));
  const expectedMissing = new Set(item.expected.missingRequirements.map(normalizeTerm));
  const expectedPresent = new Set(item.expected.presentRequirements.map(normalizeTerm));
  const truePositives = [...predictedMissing].filter(term => expectedMissing.has(term));
  const falsePositives = [...predictedMissing].filter(term => !expectedMissing.has(term));
  const falseNegatives = [...expectedMissing].filter(term => !predictedMissing.has(term));
  const presentMarkedMissing = [...expectedPresent].filter(term => predictedMissing.has(term));
  const rendered = JSON.stringify(result).toLocaleLowerCase('en-US');
  const inventedFacts = item.expected.mustNotInvent.filter(term => rendered.includes(normalizeTerm(term)));

  return {
    id: item.id,
    truePositives: truePositives.length,
    falsePositives: falsePositives.length,
    falseNegatives: falseNegatives.length,
    presentMarkedMissing,
    inventedFacts,
    overallScore: result.overallScore,
  };
}

function summarize(scores) {
  const totals = scores.reduce((sum, score) => ({
    tp: sum.tp + score.truePositives,
    fp: sum.fp + score.falsePositives,
    fn: sum.fn + score.falseNegatives,
    invented: sum.invented + score.inventedFacts.length,
    presentMarkedMissing: sum.presentMarkedMissing + score.presentMarkedMissing.length,
  }), { tp: 0, fp: 0, fn: 0, invented: 0, presentMarkedMissing: 0 });
  return {
    cases: scores.length,
    missingKeywordPrecision: totals.tp + totals.fp ? totals.tp / (totals.tp + totals.fp) : 0,
    hardRequirementRecall: totals.tp + totals.fn ? totals.tp / (totals.tp + totals.fn) : 0,
    inventedFactCount: totals.invented,
    presentRequirementFalsePositiveCount: totals.presentMarkedMissing,
  };
}

async function runLiveBenchmark({ benchmark, limit, repeats, model }) {
  if (!process.env.ANTHROPIC_API_KEY) throw new Error('ANTHROPIC_API_KEY is required for a live benchmark');
  // Supply harmless placeholders so importing the app does not enter degraded mode.
  process.env.STRIPE_SECRET_KEY ||= 'sk_test_benchmark';
  process.env.STRIPE_WEBHOOK_SECRET ||= 'whsec_benchmark';
  process.env.STRIPE_PRICE_ID ||= 'price_benchmark';
  process.env.JWT_SECRET ||= 'benchmark-only-secret-that-is-not-used-for-http-requests';
  process.env.UPSTASH_REDIS_REST_URL ||= 'https://benchmark.invalid';
  process.env.UPSTASH_REDIS_REST_TOKEN ||= 'benchmark';
  const Anthropic = require('@anthropic-ai/sdk');
  const app = require('../server');
  const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  const selected = benchmark.cases.slice(0, limit || benchmark.cases.length);
  const scores = [];
  const repeatedScores = new Map();

  for (const item of selected) {
    for (let run = 0; run < repeats; run++) {
      const result = await app.__test.analyzeCv(item.resumeText, item.jobDescription, { client, model });
      scores.push(scoreResult(item, result));
      const values = repeatedScores.get(item.id) || [];
      values.push(result.overallScore);
      repeatedScores.set(item.id, values);
      process.stderr.write(`completed ${item.id} run ${run + 1}/${repeats}\n`);
    }
  }

  const summary = summarize(scores);
  const spreads = [...repeatedScores.values()].map(values => Math.max(...values) - Math.min(...values));
  summary.maximumRepeatedScoreSpread = Math.max(0, ...spreads);
  summary.model = model;
  summary.repeats = repeats;
  return { summary, scores };
}

async function main() {
  const args = Object.fromEntries(process.argv.slice(2).map(arg => {
    const [key, value = 'true'] = arg.replace(/^--/, '').split('=');
    return [key, value];
  }));
  const fixture = path.resolve(args.fixture || DEFAULT_FIXTURE);
  const benchmark = JSON.parse(fs.readFileSync(fixture, 'utf8'));
  const errors = validateBenchmark(benchmark);
  if (errors.length) throw new Error(`Invalid benchmark:\n- ${errors.join('\n- ')}`);

  if (!args.live) {
    console.log(`quality_fixture_ok: ${benchmark.cases.length} cases across ${ROLE_FAMILIES.length} role families`);
    return;
  }

  const limit = args.limit ? Number(args.limit) : undefined;
  const repeats = args.repeats ? Number(args.repeats) : 1;
  if (limit !== undefined && (!Number.isInteger(limit) || limit < 1)) throw new Error('--limit must be a positive integer');
  if (!Number.isInteger(repeats) || repeats < 1 || repeats > 3) throw new Error('--repeats must be an integer from 1 to 3');
  const model = args.model || process.env.LLM_MODEL;
  if (!model) throw new Error('Set LLM_MODEL or pass --model=<exact-model-id>');
  const report = await runLiveBenchmark({ benchmark, limit, repeats, model });
  console.log(JSON.stringify(report, null, 2));
  if (report.summary.inventedFactCount > 0 || report.summary.missingKeywordPrecision < 0.9 || report.summary.hardRequirementRecall < 0.85) {
    process.exitCode = 1;
  }
}

if (require.main === module) main().catch(error => {
  console.error(`quality_benchmark_failed: ${error.message}`);
  process.exit(1);
});

module.exports = { ROLE_FAMILIES, validateBenchmark, scoreResult, summarize };
