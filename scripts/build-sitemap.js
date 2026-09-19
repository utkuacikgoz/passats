#!/usr/bin/env node
/**
 * Regenerates public/sitemap.xml with a truthful <lastmod> per URL.
 *
 * The dates were hand-written and had frozen at 2026-07-18 across all three
 * URLs while the pages kept changing. Each entry now takes the last commit date
 * of the file that actually renders it, falling back to the file's mtime for a
 * dirty working tree.
 *
 * Usage: npm run sync:seo
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const { CANONICAL_ORIGIN: ORIGIN } = require('../config/site');

const PAGES = [
  { url: '/',        source: 'views/index.html',   changefreq: 'weekly',  priority: '1.0' },
  { url: '/ats-checklist', source: 'views/checklist.html', changefreq: 'monthly', priority: '0.8' },
  // The free tool. Higher priority than the guides: it is the page most likely
  // to earn a link, and the only one that does something rather than explain it.
  { url: '/ats-parse-preview', source: 'views/parse-preview.html', changefreq: 'monthly', priority: '0.9' },
  { url: '/resume-summary-examples', source: 'views/guides/resume-summary-examples.html', changefreq: 'monthly', priority: '0.7' },
  { url: '/tailor-resume-to-job-description', source: 'views/guides/tailor-resume-to-job-description.html', changefreq: 'monthly', priority: '0.7' },
  { url: '/resume-length', source: 'views/guides/resume-length.html', changefreq: 'monthly', priority: '0.7' },
  // The two chat-assistant pages answer the question a visitor asks before
  // they consider paying for anything: why not just use the free thing I
  // already have open. Slightly higher priority than the rest of the set.
  { url: '/chatgpt-resume-ats-check', source: 'views/guides/chatgpt-resume-ats-check.html', changefreq: 'monthly', priority: '0.8' },
  { url: '/ai-resume-prompts', source: 'views/guides/ai-resume-prompts.html', changefreq: 'monthly', priority: '0.8' },
  { url: '/free-vs-paid-ats-checker', source: 'views/guides/free-vs-paid-ats-checker.html', changefreq: 'monthly', priority: '0.8' },
  { url: '/ats-checker-vs-chatgpt-vs-recruiter', source: 'views/guides/ats-checker-vs-chatgpt-vs-recruiter.html', changefreq: 'monthly', priority: '0.8' },
  { url: '/ats-checker-comparison', source: 'views/guides/ats-checker-comparison.html', changefreq: 'monthly', priority: '0.7' },
  { url: '/resume-keywords', source: 'views/guides/resume-keywords.html', changefreq: 'monthly', priority: '0.7' },
  { url: '/ats-score-guide', source: 'views/guides/ats-score-guide.html', changefreq: 'monthly', priority: '0.7' },
  { url: '/resume-file-format', source: 'views/guides/resume-file-format.html', changefreq: 'monthly', priority: '0.7' },
  { url: '/ats-parsing-errors', source: 'views/guides/ats-parsing-errors.html', changefreq: 'monthly', priority: '0.7' },
  { url: '/ats-resume-template', source: 'views/guides/ats-resume-template.html', changefreq: 'monthly', priority: '0.7' },
  // Who runs this, how the score is computed, and what the report will not
  // claim. Higher priority than the legal pages: it is the page a cautious
  // buyer and an AI answer engine both reach for before trusting a number.
  { url: '/about', source: 'views/about.html', changefreq: 'monthly', priority: '0.6' },
  { url: '/privacy', source: 'views/privacy.html', changefreq: 'monthly', priority: '0.3' },
  { url: '/terms',   source: 'views/terms.html',   changefreq: 'monthly', priority: '0.3' },
];

function lastModified(relativePath) {
  const absolute = path.join(ROOT, relativePath);
  try {
    const committed = execFileSync('git', ['log', '-1', '--format=%cs', '--', relativePath], {
      cwd: ROOT,
      encoding: 'utf8',
    }).trim();
    const dirty = execFileSync('git', ['status', '--porcelain', '--', relativePath], {
      cwd: ROOT,
      encoding: 'utf8',
    }).trim();
    if (committed && !dirty) return committed;
  } catch { /* not a git checkout — fall through to mtime */ }
  return fs.statSync(absolute).mtime.toISOString().slice(0, 10);
}

const body = PAGES.map(page => `  <url>
    <loc>${ORIGIN}${page.url}</loc>
    <lastmod>${lastModified(page.source)}</lastmod>
    <changefreq>${page.changefreq}</changefreq>
    <priority>${page.priority}</priority>
  </url>`).join('\n');

const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${body}
</urlset>
`;

fs.writeFileSync(path.join(ROOT, 'public', 'sitemap.xml'), xml);
console.log(`Wrote public/sitemap.xml (${PAGES.length} URLs).`);
