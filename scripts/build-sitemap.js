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
