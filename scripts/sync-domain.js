#!/usr/bin/env node
'use strict';

/**
 * Rewrites every hardcoded site origin and contact address in the static files
 * from config/site.js.
 *
 * These literals live in canonicals, Open Graph and Twitter tags, three JSON-LD
 * blocks, robots.txt, llms.txt and the printed report footer. Hand-editing them
 * is how one gets missed, and a missed canonical points Google at a host you no
 * longer own. CI runs this and fails on a diff, so the committed files can never
 * disagree with the config.
 *
 * Usage: npm run sync:domain
 */
const fs = require('fs');
const path = require('path');
const site = require('../config/site');

const ROOT = path.join(__dirname, '..');
const FILES = [
  'views/index.html',
  'views/terms.html',
  'views/privacy.html',
  'views/404.html',
  'public/robots.txt',
  'public/llms.txt',
];

// Matches any passats host, however many labels it has, so a later move needs
// no code change. The (?:\.[a-z0-9-]+)+ is load-bearing: matching a single label
// turns passats.vercel.app into passats.pro + a stranded ".app".
const HOST = String.raw`passats(?:\.[a-z0-9-]+)+`;
const ORIGIN_RE = new RegExp(String.raw`https?://(?:www\.)?${HOST}(?::\d+)?`, 'gi');
// Bare host mentions in prose, e.g. the print footer. A preceding @ is excluded
// so this cannot eat the domain half of an address.
const BARE_HOST_RE = new RegExp(String.raw`(?<![@\w])(?:www\.)?${HOST}(?![\w@-])`, 'gi');
const EMAIL_RE = new RegExp(String.raw`\b([a-z][a-z0-9._-]*)@${HOST}\b`, 'gi');

const host = new URL(site.CANONICAL_ORIGIN).host;

// Trader identity placeholders on the legal pages. The address clause appears
// only when an address is configured, so an unset value produces a correct
// sentence rather than a visible [PLACEHOLDER] on a live legal page.
const addressClause = site.REGISTERED_ADDRESS ? ` at <strong>${site.REGISTERED_ADDRESS}</strong>` : '';
const LEGAL = [
  [/\[LEGAL ENTITY NAME\]/g, site.LEGAL_ENTITY],
  [/\[JURISDICTION\]/g, site.JURISDICTION],
  // The placeholder sits inside <strong> tags, so the clause has to be matched
  // with its markup: replacing the token alone leaves a stray empty <strong>.
  [/ at <strong>\[REGISTERED ADDRESS\]<\/strong>/g, addressClause],
  // Repairs an already-emptied clause, and keeps a second run a no-op.
  [/ at <strong><\/strong>/g, addressClause],
];

let changed = 0;

for (const relative of FILES) {
  const absolute = path.join(ROOT, relative);
  if (!fs.existsSync(absolute)) continue;
  const before = fs.readFileSync(absolute, 'utf8');
  let after = before
    .replace(ORIGIN_RE, site.CANONICAL_ORIGIN)
    .replace(BARE_HOST_RE, host)
    .replace(EMAIL_RE, (_, local) => `${local}@${site.MAIL_DOMAIN}`);
  for (const [pattern, value] of LEGAL) after = after.replace(pattern, value);
  if (after !== before) {
    fs.writeFileSync(absolute, after);
    console.log(`rewrote ${relative}`);
    changed++;
  }
}

console.log(`domain_sync_ok: ${site.CANONICAL_ORIGIN}, ${changed} file(s) changed`);
