const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const benchmark = require('./fixtures/ats-golden-set.json');
const { ROLE_FAMILIES, validateBenchmark, scoreResult, summarize } = require('../scripts/quality-benchmark');

describe('ATS quality benchmark', () => {
  it('contains 60 valid, balanced synthetic cases', () => {
    assert.deepEqual(validateBenchmark(benchmark), []);
    assert.equal(benchmark.cases.length, 60);
    for (const family of ROLE_FAMILIES) {
      assert.equal(benchmark.cases.filter(item => item.roleFamily === family).length, 10);
    }
  });

  it('scores expected missing requirements without false positives', () => {
    const item = benchmark.cases[0];
    const score = scoreResult(item, {
      overallScore: 72,
      keywordsMissing: item.expected.missingRequirements,
      topFixes: ['Add the missing requirements that are true for your experience.'],
    });
    assert.equal(score.truePositives, 2);
    assert.equal(score.falsePositives, 0);
    assert.equal(score.falseNegatives, 0);
    assert.deepEqual(score.inventedFacts, []);
    assert.deepEqual(score.presentMarkedMissing, []);
  });

  it('detects invented facts and present skills incorrectly called missing', () => {
    const item = benchmark.cases[0];
    const score = scoreResult(item, {
      overallScore: 40,
      keywordsMissing: [item.expected.presentRequirements[0], 'unrelated term'],
      topFixes: [`Claim ${item.expected.mustNotInvent[0]}.`],
    });
    assert.equal(score.falsePositives, 2);
    assert.deepEqual(score.presentMarkedMissing, [item.expected.presentRequirements[0].toLowerCase()]);
    assert.deepEqual(score.inventedFacts, [item.expected.mustNotInvent[0]]);
  });

  it('summarizes precision, recall, and unsafe output counts', () => {
    const report = summarize([
      { truePositives: 2, falsePositives: 0, falseNegatives: 0, inventedFacts: [], presentMarkedMissing: [] },
      { truePositives: 1, falsePositives: 1, falseNegatives: 1, inventedFacts: ['invented'], presentMarkedMissing: ['present'] },
    ]);
    assert.equal(report.missingKeywordPrecision, 0.75);
    assert.equal(report.hardRequirementRecall, 0.75);
    assert.equal(report.inventedFactCount, 1);
    assert.equal(report.presentRequirementFalsePositiveCount, 1);
  });
});
