#!/usr/bin/env node
/**
 * Renders the PassATS wordmark to public/logo*.svg and public/logo*.png.
 *
 * The wordmark is DM Serif Display, which the site loads from Google Fonts at
 * runtime. A logo file cannot rely on that: a directory, a press kit or an email
 * client renders the SVG with whatever fonts it has, and a <text> element in a
 * font nobody installed renders as Times, or as nothing. So the glyphs are
 * converted to paths here, the same reason public/favicon.svg draws its P as a
 * path rather than setting type.
 *
 * The font is vendored at assets/fonts/ so this stays reproducible offline and
 * the output cannot drift when Google reissues the file.
 *
 * Usage: npm run build:logo
 */
const fs = require('fs');
const path = require('path');
const opentype = require('opentype.js');
const { createCanvas, loadImage } = require('@napi-rs/canvas');

const ROOT = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const FONT_PATH = path.join(ROOT, 'assets', 'fonts', 'DMSerifDisplay-Regular.ttf');

// Read from tokens.css so the logo cannot drift from the site's palette.
const tokens = fs.readFileSync(path.join(PUBLIC_DIR, 'tokens.css'), 'utf8');
const token = name => {
  const found = new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{3,8})`).exec(tokens);
  if (!found) throw new Error(`tokens.css has no --${name}`);
  return found[1];
};

const INK = token('ink');
const CREAM = token('card');
// The wordmark uses the accessible accent, not the display one: at logo sizes
// this is small text, and the header lockup is the exact element axe flagged.
const ACCENT = token('accent-strong');

const SIZE = 200;          // font size in the SVG's own units; the viewBox scales
// No tracking. The site sets letter-spacing: -0.02em on .logo, but opentype's
// letterSpacing option is what produced the NaN coordinates described below, and
// two percent of tracking is not worth a corrupt outline. The natural advances
// render correctly and the difference is invisible at logo sizes.
const PAD = 0.12;          // padding as a fraction of the cap height

// A fresh parse per run. opentype hands back glyph paths that share mutable
// state across calls: laying 'Pass' out glyph by glyph emitted literal NaN
// coordinates into the third glyph, which SVG renders by abandoning the path
// mid-outline. The wordmark came out as 'Pa' plus two fragments, and every
// intermediate check — command counts, bounding boxes, subpath counts — looked
// correct, because the corruption is in the serialised numbers only. Parsing
// per run costs a few milliseconds in a build script and removes the class.
const loadFont = () => opentype.parse(fs.readFileSync(FONT_PATH).buffer.slice(0));

/**
 * Draw a run one glyph at a time, each at the origin, positioned with a
 * transform.
 *
 * opentype corrupts this font's outlines whenever it bakes a non-zero x into
 * the coordinates: the 's' of 'Pass' lands at x=216.6 and serialises with
 * literal NaN values, while the same glyph at the origin is perfect. SVG renders
 * a NaN by abandoning the path there, so the wordmark came out as 'Pa' plus two
 * fragments. Nothing cheap caught it — command counts, subpath counts and
 * bounding boxes were all correct, because only the serialised numbers are
 * wrong, and 'Pa', 'as', 'ss' and 'ATS' are each clean in isolation.
 *
 * Drawing at the origin and translating sidesteps the arithmetic entirely and
 * costs nothing: the transform is exact.
 */
function run(text, startX) {
  const font = loadFont();
  let x = startX;
  const glyphs = [];
  const box = { x1: Infinity, y1: Infinity, x2: -Infinity, y2: -Infinity };
  for (const char of text) {
    const glyph = font.charToGlyph(char).getPath(0, 0, SIZE);
    const data = glyph.toPathData(2);
    // The guard is the point. Without it the build ships a broken wordmark and
    // the only symptom is a logo that looks wrong to a human.
    if (/NaN|Infinity|undefined/.test(data)) {
      throw new Error(`glyph "${char}" of "${text}" serialised with invalid coordinates`);
    }
    glyphs.push({ data, x });
    const bounds = glyph.getBoundingBox();
    box.x1 = Math.min(box.x1, bounds.x1 + x);
    box.y1 = Math.min(box.y1, bounds.y1);
    box.x2 = Math.max(box.x2, bounds.x2 + x);
    box.y2 = Math.max(box.y2, bounds.y2);
    x += font.getAdvanceWidth(char, SIZE);
  }
  return { glyphs, box, endX: x };
}

const paths = (runData, fill) => runData.glyphs
  .map(g => `\n  <path fill="${fill}" transform="translate(${g.x.toFixed(2)} 0)" d="${g.data}"/>`)
  .join('');

const pass = run('Pass', 0);
const ats = run('ATS', pass.endX);

// A tight box around the drawn glyphs, not the font's line box: the line box
// carries ascender and descender space this wordmark never uses, and it would
// show up as lopsided padding wherever the logo is placed.
const bounds = {
  y1: Math.min(pass.box.y1, ats.box.y1),
  y2: Math.max(pass.box.y2, ats.box.y2),
};
const capHeight = bounds.y2 - bounds.y1;
const pad = capHeight * PAD;
const width = ats.box.x2;
const boxX = -pad;
const boxY = bounds.y1 - pad;
const boxW = width + pad * 2;
const boxH = capHeight + pad * 2;
const viewBox = [boxX, boxY, boxW, boxH].map(n => Number(n.toFixed(2))).join(' ');

function svg({ passFill, atsFill, background }) {
  const bg = background
    ? `\n  <rect x="${boxX.toFixed(2)}" y="${boxY.toFixed(2)}" width="${boxW.toFixed(2)}" height="${boxH.toFixed(2)}" fill="${background}"/>`
    : '';
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${viewBox}" role="img" aria-label="PassATS">
  <title>PassATS</title>${bg}
${paths(pass, passFill)}${paths(ats, atsFill)}
</svg>
`;
}

const variants = [
  ['logo.svg', { passFill: INK, atsFill: ACCENT, background: null }],
  ['logo-dark.svg', { passFill: CREAM, atsFill: ACCENT, background: null }],
  ['logo-mono.svg', { passFill: INK, atsFill: INK, background: null }],
];

(async () => {
  for (const [name, options] of variants) {
    fs.writeFileSync(path.join(PUBLIC_DIR, name), svg(options));
  }

  // Raster copies for the places that will not take an SVG — directory
  // submissions and social profiles mostly want PNG with transparency.
  const aspect = boxH / boxW;
  for (const [source, target, pngWidth] of [
    ['logo.svg', 'logo.png', 800],
    ['logo.svg', 'logo@2x.png', 1600],
    ['logo-dark.svg', 'logo-dark.png', 800],
  ]) {
    const height = Math.round(pngWidth * aspect);
    const image = await loadImage(fs.readFileSync(path.join(PUBLIC_DIR, source)));
    const canvas = createCanvas(pngWidth, height);
    canvas.getContext('2d').drawImage(image, 0, 0, pngWidth, height);
    fs.writeFileSync(path.join(PUBLIC_DIR, target), canvas.toBuffer('image/png'));
  }

  const written = [...variants.map(v => v[0]), 'logo.png', 'logo@2x.png', 'logo-dark.png'];
  console.log(`logo_built_ok: ${written.join(', ')} (wordmark ${Math.round(width)}x${Math.round(capHeight)} units, accent ${ACCENT})`);
})().catch(err => {
  console.error('logo build failed:', err.message);
  process.exit(1);
});
