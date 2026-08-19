#!/usr/bin/env node
/**
 * Renders public/og-image.svg to public/og-image.png (1200x630).
 *
 * The share card drifted two rewrites behind the live page — it still carried
 * "You're getting filtered by a robot" and a CTA the site no longer used. Keeping
 * the PNG generated from the SVG means one edit updates both.
 *
 * Uses @napi-rs/canvas, which the project already depends on for PDF parsing.
 * Run it locally after editing the SVG: `npm run build:og`.
 */
const fs = require('fs');
const path = require('path');
const { createCanvas, loadImage } = require('@napi-rs/canvas');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const SVG_PATH = path.join(PUBLIC_DIR, 'og-image.svg');
const PNG_PATH = path.join(PUBLIC_DIR, 'og-image.png');

(async () => {
  const svg = fs.readFileSync(SVG_PATH);
  const image = await loadImage(svg);
  const canvas = createCanvas(1200, 630);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(image, 0, 0, 1200, 630);
  fs.writeFileSync(PNG_PATH, canvas.toBuffer('image/png'));
  console.log(`Wrote ${path.relative(process.cwd(), PNG_PATH)} (1200x630)`);
})().catch(err => {
  console.error('OG image build failed:', err.message);
  process.exit(1);
});
