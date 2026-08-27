#!/usr/bin/env node
'use strict';

/**
 * Renders content/guides.js into views/guides/<slug>.html.
 *
 * The shell — nav, footer, canonical, Open Graph, Article schema, the CTA, the
 * mobile tap-target rules — is defined once here. Hand-writing five near
 * identical documents guarantees they drift: one gets a canonical fix, another
 * does not, and nobody notices until a crawler does.
 *
 * The domain comes from config/site.js, so these need no sync-domain pass.
 *
 * Usage: npm run build:guides
 */
const fs = require('fs');
const path = require('path');
const site = require('../config/site');
const guides = require('../content/guides');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'views', 'guides');
const ORIGIN = site.CANONICAL_ORIGIN;

// Escape for an HTML attribute. Body copy is authored HTML and passes through.
const attr = s => String(s).replace(/&(?!(?:amp|lt|gt|quot|#\d+);)/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

function render(guide, siblings) {
  const url = `${ORIGIN}/${guide.slug}`;
  const related = siblings
    .filter(g => g.slug !== guide.slug)
    .map(g => `        <li><a href="/${g.slug}">${g.h1}</a></li>`)
    .join('\n');

  const body = guide.sections.map(s => `
  <h2>${s.h2}</h2>
${s.body.map(p => `  <p>${p}</p>`).join('\n')}`).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${attr(guide.title)} | PassATS</title>
<meta name="description" content="${attr(guide.description)}">
<link rel="canonical" href="${url}">

<meta property="og:type" content="article">
<meta property="og:url" content="${url}">
<meta property="og:title" content="${attr(guide.title)}">
<meta property="og:description" content="${attr(guide.description)}">
<meta property="og:image" content="${ORIGIN}/og-image.png">
<meta property="og:site_name" content="PassATS">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${attr(guide.title)}">
<meta name="twitter:description" content="${attr(guide.description)}">
<meta name="twitter:image" content="${ORIGIN}/og-image.png">
<meta name="robots" content="index, follow">

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">

<!-- Vercel Web Analytics -->
<script>
  window.va = window.va || function () { (window.vaq = window.vaq || []).push(arguments); };
</script>
<script defer src="/_vercel/insights/script.js"></script>
<script src="https://analytics.ahrefs.com/analytics.js" data-key="bnqpzy5Q4W2L+XtzZBbWjQ" async></script>
<link rel="stylesheet" href="/tokens.css">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--ink); min-height: 100vh; }
  nav { padding: 20px 40px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; gap: 16px; }
  .logo { font-family: 'DM Serif Display', 'Iowan Old Style', 'Palatino Linotype', Palatino, Georgia, serif; font-size: 1.4rem; text-decoration: none; color: var(--ink); }
  .logo span { color: var(--accent); }
  .nav-cta { background: var(--ink); color: #fff; padding: 8px 18px; border-radius: 100px; font-size: 0.82rem; font-weight: 500; text-decoration: none; white-space: nowrap; }
  main { max-width: 680px; margin: 0 auto; padding: 56px 40px 40px; }
  h1 { font-family: 'DM Serif Display', 'Iowan Old Style', 'Palatino Linotype', Palatino, Georgia, serif; font-size: clamp(2rem, 5vw, 2.6rem); line-height: 1.15; margin-bottom: 18px; text-wrap: balance; }
  .standfirst { font-size: 1.02rem; color: var(--ink); line-height: 1.65; margin-bottom: 8px; }
  .meta { font-size: 0.85rem; color: var(--muted); margin-bottom: 8px; }
  h2 { font-family: 'DM Serif Display', 'Iowan Old Style', 'Palatino Linotype', Palatino, Georgia, serif; font-size: 1.45rem; margin: 40px 0 8px; line-height: 1.25; }
  p, li { font-size: 0.95rem; color: var(--muted); line-height: 1.78; margin-bottom: 12px; }
  ul { padding-left: 22px; }
  a { color: var(--accent); }
  strong { color: var(--ink); font-weight: 600; }
  code { background: var(--surface); border: 1px solid var(--border); border-radius: 3px; padding: 1px 5px; font-size: 0.88em; }
  .cta { background: var(--card); border: 1px solid var(--border); border-radius: 16px; padding: 28px 26px; margin: 48px 0 0; text-align: center; }
  .cta h2 { margin-top: 0; font-size: 1.35rem; }
  .cta p { margin-bottom: 18px; }
  .cta a.btn { display: inline-block; background: var(--accent); color: #fff; text-decoration: none; padding: 14px 30px; border-radius: 12px; font-weight: 600; font-size: 0.95rem; }
  .related { margin-top: 44px; border-top: 1px solid var(--border); padding-top: 24px; }
  .related h2 { font-size: 1.1rem; margin: 0 0 10px; font-family: inherit; font-weight: 600; color: var(--ink); }
  .related ul { list-style: none; padding: 0; }
  .related li { margin-bottom: 8px; }
  :focus-visible { outline: 3px solid var(--accent); outline-offset: 2px; border-radius: 4px; }
  footer { max-width: 680px; margin: 0 auto; padding: 30px 40px 50px; text-align: center; font-size: 0.82rem; color: var(--muted); border-top: 1px solid var(--border); }
  /* Separators as gaps, not middots: a wrapped line used to end on a dangling
     middot, with the last link stranded on the row below. */
  .footer-legal { display: flex; flex-wrap: wrap; justify-content: center; align-items: center; gap: 2px 18px; }

  /* Touch targets: 44px is the minimum both Apple and Google publish. */
  @media (max-width: 640px) {
    nav { padding: 16px 20px; }
    main { padding: 36px 20px 30px; }
    footer { padding: 24px 20px 40px; }
    .logo, footer a, .nav-cta, .btn, .cta a.btn {
      min-height: 44px; display: inline-flex; align-items: center; justify-content: center;
    }
    footer p { line-height: 2.4; }
    /* The related-guide list is how a reader moves between guides on a phone.
       At 35px the rows sat under the tap-target minimum and close enough
       together to hit the wrong one; rules between them make the list scan. */
    .related li { margin-bottom: 0; }
    .related a {
      display: flex; align-items: center; justify-content: flex-start;
      min-height: 44px; border-bottom: 1px solid var(--border);
      text-decoration: none;
    }
  }
</style>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon.ico" sizes="16x16 32x32 48x48">
<meta name="theme-color" content="#D85D43">

<script type="application/ld+json">
${JSON.stringify({
  '@context': 'https://schema.org',
  '@type': 'Article',
  headline: guide.title,
  description: guide.description,
  image: `${ORIGIN}/og-image.png`,
  author: { '@type': 'Organization', name: 'PassATS', url: ORIGIN },
  publisher: { '@type': 'Organization', name: 'PassATS', url: ORIGIN },
  mainEntityOfPage: { '@type': 'WebPage', '@id': url },
}, null, 2)}
</script>
</head>
<body>
<nav>
  <a class="logo" href="/">Pass<span>ATS</span></a>
  <a class="nav-cta" href="/">Check My Resume. $2.99</a>
</nav>
<main>
  <h1>${guide.h1}</h1>
  <p class="standfirst">${guide.standfirst}</p>
  <p class="meta">From the team behind PassATS. Free to read, no email required.</p>
${body}

  <div class="cta">
    <h2>See which of these apply to your resume</h2>
    <p>PassATS reads your file and names the specific lines to change, with what each fix is worth. One report, $2.99, no account, nothing stored.</p>
    <a class="btn" href="/">Check My Resume. $2.99</a>
  </div>

  <div class="related">
    <h2>Related guides</h2>
    <ul>
        <li><a href="/ats-parse-preview">See what an ATS reads from your resume</a></li>
${related}
        <li><a href="/ats-checklist">The ATS Resume Checklist</a></li>
    </ul>
  </div>
</main>
<footer>
  <p class="footer-legal"><span>&copy; 2026 PassATS</span> <a href="/">Home</a> <a href="/privacy">Privacy</a> <a href="/terms">Terms</a></p>
</footer>
</body>
</html>
`;
}

fs.mkdirSync(OUT, { recursive: true });
const written = [];
for (const guide of guides) {
  const file = path.join(OUT, `${guide.slug}.html`);
  fs.writeFileSync(file, render(guide, guides));
  written.push(guide.slug);
}
console.log(`guides_built_ok: ${written.length} pages (${written.join(', ')})`);
