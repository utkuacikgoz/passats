/**
 * Tests for the prompt evaluation harness.
 *
 * The harness itself calls the real model and costs money, so it cannot run in
 * CI. Its judgement is pure though, and that is the part that must be right: a
 * checker that silently passes everything is worse than no checker, because it
 * would certify a prompt regression as clean.
 *
 * Usage: node --test test/eval.test.js
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { checkReport, summarise, prose } = require('../scripts/eval-prompt');

function report(overrides = {}) {
  return {
    overallScore: 72,
    verdict: 'Needs Work',
    verdictDetail: 'Your Revolut role has 3 quantified bullets, but no Skills section exists.',
    detectedRole: 'Software Engineer',
    metrics: {
      keywords: { score: 65, note: 'No Skills section detected. CI/CD appears nowhere in the text.' },
      formatting: { score: 78, note: 'Your EXPERIENCE and EDUCATION headings are standard.' },
      readability: { score: 80, note: 'Bullets average 14 words across the document.' },
      contactInfo: { score: 90, note: 'Email and phone are present. No LinkedIn URL.' },
    },
    issues: [
      { severity: 'critical', title: 'No Skills section', detail: 'Your CV jumps from the summary straight to EXPERIENCE. Add a Skills section.' },
      { severity: 'warning', title: 'Abstract verbs', detail: '3 of 4 bullets in the Accenture entry open with led or drove and carry no number.' },
      { severity: 'pass', title: 'Quantified results', detail: 'Three Revolut bullets name a figure, including the 40 percent reduction.' },
    ],
    keywordsFound: ['TypeScript', 'React'],
    keywordsMissing: ['CI/CD', 'Docker'],
    topFixes: [
      'Add a Skills section after your summary listing TypeScript and React. Expected score impact: +12 points.',
      'Rewrite the 2nd Accenture bullet to name the outcome. Expected score impact: +9 points.',
      'Add your LinkedIn URL to the contact line. Expected score impact: +6 points.',
    ],
    ...overrides,
  };
}

describe('checkReport accepts a compliant report', () => {
  it('finds nothing wrong with output that follows every rule', () => {
    assert.deepEqual(checkReport(report()), []);
  });

  it('allows ordinary hyphens in compound words', () => {
    // The prompt bans em dashes, en dashes and double hyphens. Banning the
    // hyphen too would forbid correct English, which is the P2 finding.
    const withCompounds = report({
      topFixes: [
        'Name your cross-functional work in the Revolut entry. Expected score impact: +8 points.',
        'Add front-end frameworks to a Skills section. Expected score impact: +7 points.',
        'State the data-driven outcome in bullet 3. Expected score impact: +5 points.',
      ],
    });
    assert.deepEqual(checkReport(withCompounds), []);
  });
});

describe('checkReport catches every rule the prompt sets', () => {
  const cases = [
    ['banned hedging phrase', { verdictDetail: 'Consider adding a Skills section to your CV document.' }, /banned phrase: "consider"/],
    ['em dash', { verdictDetail: 'Your CV is strong — but the Skills section is missing entirely.' }, /em dash/],
    ['en dash', { verdictDetail: 'Your dates run 2019–2022 with no Skills section anywhere here.' }, /em dash/],
    ['double hyphen', { verdictDetail: 'Your CV is strong -- but the Skills section is missing here.' }, /em dash/],
    ['layout claim', { verdictDetail: 'Your single-column layout parses cleanly with no tables present.' }, /visual layout/],
    ['too few fixes', { topFixes: ['Add a Skills section. Expected score impact: +12 points.'] }, /topFixes, prompt requires 3 to 5/],
    ['too many issues', { issues: new Array(9).fill({ severity: 'pass', title: 'x', detail: 'y'.repeat(50) }) }, /issues, prompt requires 3 to 7/],
    ['too many keywords found', { keywordsFound: new Array(9).fill('React') }, /more than 8 keywordsFound/],
    ['too many keywords missing', { keywordsMissing: new Array(7).fill('Docker') }, /more than 6 keywordsMissing/],
    ['fix without score impact', {
      topFixes: ['Add a Skills section.', 'Quantify your bullets.', 'Add a LinkedIn URL.'],
    }, /omit an expected score impact/],
    ['vague issue detail', {
      issues: [
        { severity: 'critical', title: 'Keywords', detail: 'Add more keywords.' },
        { severity: 'warning', title: 'Dates', detail: 'Your dates are inconsistent across the Accenture and Monzo entries.' },
        { severity: 'pass', title: 'Contact', detail: 'Your email and phone number are both present at the top.' },
      ],
    }, /too short to be specific/],
    ['score out of range', { overallScore: 140 }, /score out of range/],
    ['score as a decimal', { overallScore: 0.72 }, /score out of range or non-integer/],
  ];

  for (const [name, override, pattern] of cases) {
    it(`flags ${name}`, () => {
      const problems = checkReport(report(override));
      assert.ok(problems.length > 0, `${name} was not flagged at all`);
      assert.ok(problems.some(p => pattern.test(p)), `expected ${pattern}, got: ${problems.join('; ')}`);
    });
  }
});

describe('prose collects every customer-facing string', () => {
  it('reaches verdict, metric notes, issues, and fixes', () => {
    const lines = prose(report());
    assert.ok(lines.some(l => l.includes('Revolut role')), 'verdictDetail');
    assert.ok(lines.some(l => l.includes('CI/CD appears nowhere')), 'metric note');
    assert.ok(lines.some(l => l.includes('Abstract verbs')), 'issue title');
    assert.ok(lines.some(l => l.includes('jumps from the summary')), 'issue detail');
    assert.ok(lines.some(l => l.includes('Expected score impact')), 'topFix');
  });
});

describe('summarise reports score stability', () => {
  it('measures the spread across identical runs', () => {
    const runs = [
      { report: report({ overallScore: 72 }), problems: [] },
      { report: report({ overallScore: 78 }), problems: [] },
      { report: report({ overallScore: 71 }), problems: [] },
    ];
    const s = summarise('example', runs);
    assert.equal(s.spread, 7, 'the same CV moved 7 points between identical runs');
    assert.deepEqual(s.scores, [72, 78, 71]);
    assert.equal(s.failed, 0);
  });

  it('counts failed runs without letting them skew the spread', () => {
    const runs = [
      { report: report({ overallScore: 70 }), problems: [] },
      { error: 'LLM_TIMEOUT' },
      { report: report({ overallScore: 71 }), problems: [] },
    ];
    const s = summarise('example', runs);
    assert.equal(s.failed, 1);
    assert.equal(s.spread, 1);
  });

  it('deduplicates violations but keeps the total count', () => {
    const runs = [
      { report: report(), problems: ['banned phrase: "consider"'] },
      { report: report(), problems: ['banned phrase: "consider"'] },
    ];
    const s = summarise('example', runs);
    assert.deepEqual(s.violations, ['banned phrase: "consider"']);
    assert.equal(s.violationCount, 2);
  });

  it('surfaces a role that changes between runs', () => {
    const runs = [
      { report: report({ detectedRole: 'Software Engineer' }), problems: [] },
      { report: report({ detectedRole: 'Backend Developer' }), problems: [] },
    ];
    assert.equal(summarise('example', runs).roles.length, 2, 'unstable role detection must be visible');
  });
});
