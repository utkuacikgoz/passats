#!/usr/bin/env node
/**
 * Prompt evaluation harness.
 *
 * Every quality question about this product is currently unanswerable: does the
 * same CV score the same twice, does a prompt edit help or hurt, do the findings
 * actually quote the document. This runs the real analysis over a fixture set,
 * several times each, and reports two things:
 *
 *   1. Score stability. The score is what people pay for. If the same CV swings
 *      more than a couple of points between identical runs, the number is not a
 *      product yet. This is the open P1 finding: the prompt's penalties and
 *      bonuses never say whether they apply to a component or to the total.
 *
 *   2. Rule compliance. The prompt sets hard rules about phrasing, dash
 *      characters, list lengths and fix format. These are checked mechanically,
 *      so a prompt edit that quietly breaks one shows up immediately.
 *
 * It does NOT judge whether the advice is good. Read a sample by hand for that.
 *
 * Usage:
 *   npm run eval                      # every fixture, 3 runs each
 *   npm run eval -- --runs 5          # more runs, tighter variance estimate
 *   npm run eval -- --only nurse      # one fixture
 *   npm run eval -- --json out.json   # machine-readable, for comparing versions
 *
 * Needs ANTHROPIC_API_KEY. Costs roughly $0.03 per run.
 */
const fs = require('fs');
const path = require('path');

const FIXTURE_DIR = path.join(__dirname, '..', 'eval', 'cvs');

// Straight from the OUTPUT WRITING RULES in the system prompt.
const BANNED_PHRASES = [
  "it's worth noting", 'overall', 'in order to', 'to some extent', 'keep in mind',
  'consider', 'it appears', 'seems like', 'you might want to',
  'there is room for improvement', 'well structured', 'however',
  'that being said', 'moving forward', 'leverage', 'utilize',
];

// Rule 8: the model sees extracted text, never a rendered page.
const LAYOUT_CLAIMS = /\btables?\b|\bcolumns?\b|\bgraphics\b|single[- ]column|visually clean|clean layout/i;

/** Every customer-facing string in a report, flattened. */
function prose(report) {
  return [
    report.verdictDetail,
    ...Object.values(report.metrics || {}).map(m => m && m.note),
    ...(report.issues || []).flatMap(i => [i && i.title, i && i.detail]),
    ...(report.topFixes || []),
  ].filter(Boolean);
}

/**
 * Mechanical rule checks. Returns a list of violation strings; empty is a pass.
 * Pure, so it is unit-tested without an API key.
 */
function checkReport(report) {
  const problems = [];
  const lines = prose(report);
  const all = lines.join(' ');

  for (const phrase of BANNED_PHRASES) {
    if (new RegExp(`\\b${phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(all)) {
      problems.push(`banned phrase: "${phrase}"`);
    }
  }

  // Em dash, en dash, double hyphen. Ordinary hyphens are correct English and
  // are deliberately allowed.
  if (/[–—]|--/.test(all)) problems.push('uses an em dash, en dash, or double hyphen');

  if (LAYOUT_CLAIMS.test(all)) problems.push('claims visual layout analysis the model cannot perform');

  const fixes = report.topFixes || [];
  if (fixes.length < 3 || fixes.length > 5) problems.push(`${fixes.length} topFixes, prompt requires 3 to 5`);

  const issues = report.issues || [];
  if (issues.length < 3 || issues.length > 7) problems.push(`${issues.length} issues, prompt requires 3 to 7`);

  if ((report.keywordsFound || []).length > 8) problems.push('more than 8 keywordsFound');
  if ((report.keywordsMissing || []).length > 6) problems.push('more than 6 keywordsMissing');

  // Rule 2: every fix names its expected score impact.
  const withoutImpact = fixes.filter(f => !/score impact/i.test(f)).length;
  if (withoutImpact) problems.push(`${withoutImpact} of ${fixes.length} fixes omit an expected score impact`);

  // Rule 1: findings must reference the document, not describe it generically.
  const vague = (report.issues || []).filter(i => (i.detail || '').length < 40).length;
  if (vague) problems.push(`${vague} issue details are too short to be specific`);

  const scores = [
    report.overallScore,
    ...Object.values(report.metrics || {}).map(m => m && m.score),
  ];
  for (const score of scores) {
    if (!Number.isInteger(score) || score < 0 || score > 100) {
      problems.push(`score out of range or non-integer: ${score}`);
      break;
    }
  }

  return problems;
}

/** Aggregates repeated runs of one fixture into a stability summary. */
function summarise(name, runs) {
  const ok = runs.filter(r => !r.error);
  const scores = ok.map(r => r.report.overallScore);
  const spread = scores.length ? Math.max(...scores) - Math.min(...scores) : null;
  const violations = ok.flatMap(r => r.problems);
  return {
    fixture: name,
    runs: runs.length,
    failed: runs.length - ok.length,
    scores,
    spread,
    roles: [...new Set(ok.map(r => r.report.detectedRole))],
    violations: [...new Set(violations)],
    violationCount: violations.length,
  };
}

module.exports = { checkReport, summarise, prose, BANNED_PHRASES };

// ── CLI ──────────────────────────────────────────────────────────────────────

function arg(flag, fallback) {
  const index = process.argv.indexOf(flag);
  return index === -1 ? fallback : process.argv[index + 1];
}

// Spread above this means the score is not reproducible enough to sell.
const SPREAD_BUDGET = Number(arg('--max-spread', 3));

async function main() {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('ANTHROPIC_API_KEY is required. This harness calls the real model.');
    process.exit(2);
  }
  if (!fs.existsSync(FIXTURE_DIR)) {
    console.error(`No fixtures at ${FIXTURE_DIR}`);
    process.exit(2);
  }

  process.env.DEV_MODE = '';
  const { analyzeCv } = require('../server').__test;

  const runs = Number(arg('--runs', 3));
  const only = arg('--only', null);
  const fixtures = fs.readdirSync(FIXTURE_DIR)
    .filter(f => f.endsWith('.txt'))
    .filter(f => !only || f.includes(only));

  if (fixtures.length === 0) {
    console.error('No fixtures matched.');
    process.exit(2);
  }

  console.log(`Evaluating ${fixtures.length} fixture(s), ${runs} run(s) each.\n`);
  const summaries = [];

  for (const file of fixtures) {
    const name = path.basename(file, '.txt');
    const cvText = fs.readFileSync(path.join(FIXTURE_DIR, file), 'utf8');
    const results = [];

    for (let i = 0; i < runs; i++) {
      try {
        const report = await analyzeCv(cvText, '');
        results.push({ report, problems: checkReport(report) });
        process.stdout.write(`  ${name} run ${i + 1}: ${report.overallScore}\n`);
      } catch (err) {
        results.push({ error: err.message });
        process.stdout.write(`  ${name} run ${i + 1}: FAILED (${err.message})\n`);
      }
    }
    summaries.push(summarise(name, results));
  }

  console.log('\n' + 'fixture'.padEnd(18) + 'scores'.padEnd(20) + 'spread'.padEnd(9) + 'role'.padEnd(24) + 'violations');
  console.log('-'.repeat(96));
  for (const s of summaries) {
    const flag = s.spread !== null && s.spread > SPREAD_BUDGET ? ' !' : '';
    console.log(
      s.fixture.padEnd(18) +
      s.scores.join(', ').padEnd(20) +
      `${s.spread ?? '-'}${flag}`.padEnd(9) +
      (s.roles.join(' / ') || '-').slice(0, 22).padEnd(24) +
      (s.violationCount || 0)
    );
  }

  const unstable = summaries.filter(s => s.spread !== null && s.spread > SPREAD_BUDGET);
  const offending = summaries.filter(s => s.violations.length);

  if (offending.length) {
    console.log('\nRule violations:');
    for (const s of offending) {
      for (const v of s.violations) console.log(`  ${s.fixture}: ${v}`);
    }
  }

  const jsonPath = arg('--json', null);
  if (jsonPath) {
    fs.writeFileSync(jsonPath, JSON.stringify({ generatedAt: new Date().toISOString(), runs, summaries }, null, 2));
    console.log(`\nWrote ${jsonPath}`);
  }

  console.log();
  if (unstable.length) {
    console.error(`${unstable.length} fixture(s) scored outside a ${SPREAD_BUDGET} point spread across identical runs.`);
    console.error('That is the open P1 finding: the prompt never says whether penalties and');
    console.error('bonuses apply to a component score or to the weighted total.');
  }
  if (offending.length) console.error(`${offending.length} fixture(s) broke a prompt rule.`);
  if (unstable.length || offending.length) process.exit(1);
  console.log('Stable and compliant across all fixtures.');
}

if (require.main === module) {
  main().catch(err => {
    console.error('Evaluation failed:', err.message);
    process.exit(1);
  });
}
