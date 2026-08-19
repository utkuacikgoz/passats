#!/usr/bin/env node
/**
 * Regenerates the FAQPage JSON-LD in views/index.html from the FAQ that is
 * actually visible on the page.
 *
 * The two drifted apart once already: the visible copy was rewritten while the
 * structured data kept the previous version, which is both a rich-results
 * violation (Google requires FAQ markup to match visible content) and a set of
 * product claims the analysis does not make. Generating one from the other makes
 * that class of drift impossible; test/structured-data.test.js fails the build
 * if this script has not been run.
 *
 * Usage: npm run sync:seo
 */
const fs = require('fs');
const path = require('path');

const INDEX_PATH = path.join(__dirname, '..', 'views', 'index.html');

// Matches the visible FAQ accordion entries in document order.
const FAQ_ITEM = /<details class="faq-item"[^>]*>\s*<summary>([\s\S]*?)<\/summary>\s*<p>([\s\S]*?)<\/p>\s*<\/details>/g;
const FAQ_LD_BLOCK = /(<!-- Structured Data: FAQPage[^>]*-->\s*<script type="application\/ld\+json">\s*)([\s\S]*?)(\s*<\/script>)/;

function decodeEntities(html) {
  return html
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&hellip;/g, '…')
    .replace(/&middot;/g, '·')
    .replace(/&times;/g, '×')
    .replace(/&copy;/g, '©')
    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function extractFaq(html) {
  const items = [];
  for (const match of html.matchAll(FAQ_ITEM)) {
    items.push({ question: decodeEntities(match[1]), answer: decodeEntities(match[2]) });
  }
  return items;
}

function buildFaqLd(items) {
  return {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: items.map(item => ({
      '@type': 'Question',
      name: item.question,
      acceptedAnswer: { '@type': 'Answer', text: item.answer },
    })),
  };
}

function sync(html) {
  const items = extractFaq(html);
  if (items.length === 0) throw new Error('No visible FAQ items found — has the markup changed?');
  const block = html.match(FAQ_LD_BLOCK);
  if (!block) throw new Error('FAQPage JSON-LD block not found in views/index.html');

  const json = JSON.stringify(buildFaqLd(items), null, 2);
  const updated = html.replace(FAQ_LD_BLOCK, (_, open, __, close) => `${open}${json}${close}`);
  return { html: updated, count: items.length, changed: updated !== html };
}

module.exports = { extractFaq, buildFaqLd, sync };

if (require.main === module) {
  const html = fs.readFileSync(INDEX_PATH, 'utf8');
  const result = sync(html);
  fs.writeFileSync(INDEX_PATH, result.html);
  console.log(
    result.changed
      ? `Synced FAQPage JSON-LD from ${result.count} visible FAQ entries.`
      : `FAQPage JSON-LD already matches all ${result.count} visible FAQ entries.`
  );
}
