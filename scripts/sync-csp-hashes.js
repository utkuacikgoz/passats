#!/usr/bin/env node
/**
 * Recomputes the CSP hashes in server.js from the inline scripts and event
 * handlers that views/index.html actually ships.
 *
 * The policy has no 'unsafe-inline' for scripts, so a stale hash does not
 * degrade — it blocks the entire application script and the page silently stops
 * working. Doing this by hand after every markup edit is a trap; the e2e suite
 * verifies the result independently.
 *
 * Usage: npm run sync:csp
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const INDEX_PATH = path.join(ROOT, 'views', 'index.html');
const SERVER_PATH = path.join(ROOT, 'server.js');

const hash = body => `'sha256-${crypto.createHash('sha256').update(body, 'utf8').digest('base64')}'`;

const html = fs.readFileSync(INDEX_PATH, 'utf8');

// Executable inline scripts only — application/ld+json blocks are data, not script.
const scripts = [...html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)]
  .filter(([, attributes, body]) => !attributes.includes('application/ld+json') && body.trim())
  .map(([, , body]) => body);

if (scripts.length !== 2) {
  throw new Error(`Expected 2 inline scripts (analytics shim + app), found ${scripts.length}`);
}
// Document order: the Vercel Analytics shim sits in <head>, the app at the end of <body>.
const [analyticsScript, appScript] = scripts;

const handlers = [...new Set([...html.matchAll(/\s(?:on[a-z]+)="([^"]*)"/g)].map(m => m[1]))];

let server = fs.readFileSync(SERVER_PATH, 'utf8');
const before = server;

server = server.replace(
  /const APP_SCRIPT_CSP_HASH = "[^"]*";/,
  `const APP_SCRIPT_CSP_HASH = "${hash(appScript)}";`
);
server = server.replace(
  /const VERCEL_ANALYTICS_CSP_HASH = "[^"]*";/,
  `const VERCEL_ANALYTICS_CSP_HASH = "${hash(analyticsScript)}";`
);

const handlerBlock = handlers
  .map(body => {
    const label = body.length > 46 ? `${body.slice(0, 46)}…` : body;
    return `  "${hash(body)}", // ${label}`;
  })
  .join('\n');

server = server.replace(
  /const APP_HANDLER_CSP_HASHES = \[\n[\s\S]*?\n\]\.join\(' '\);/,
  `const APP_HANDLER_CSP_HASHES = [\n${handlerBlock}\n].join(' ');`
);

if (server === before) {
  console.log('CSP hashes already current.');
} else {
  fs.writeFileSync(SERVER_PATH, server);
  console.log(`Updated CSP hashes: 2 inline scripts, ${handlers.length} inline handlers.`);
}
