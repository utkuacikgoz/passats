/**
 * Hidden-text detection for uploaded résumés.
 *
 * The threat is not prompt injection — that is contained elsewhere. It is score
 * inflation: a candidate pastes a block of keywords the human reader cannot see,
 * and the keyword metric rewards them for work they did not do. The three ways
 * to hide text in a document people actually use are:
 *
 *   PDF   text rendering mode 3 (and 7), which paints nothing
 *   PDF   fill colour equal to the page, the white-on-white trick
 *   PDF   a font scaled below the threshold of legibility
 *   DOCX  w:vanish, w:color="FFFFFF", and w:sz at a fraction of a point
 *
 * Two design rules run through everything here.
 *
 * First, a false accusation is worse than a miss. Telling a paying customer
 * their clean résumé is stuffed with hidden keywords is a far worse failure than
 * quietly missing a cheat, so every heuristic that could fire on a legitimate
 * document is gated. White text is normal on a dark sidebar, so colour findings
 * are dropped entirely on any page that paints a dark shape or an image. A tiny
 * font size is normal when the text matrix scales it back up, so size is
 * measured after the matrix, not before.
 *
 * Second, detection must never cost someone the analysis they paid for. Every
 * entry point is wrapped so that a parse failure, a timeout or an unexpected
 * document shape returns "nothing found" and leaves the extracted text alone.
 */
'use strict';

// A scanned résumé is a page image with an invisible OCR layer over it: every
// character is mode 3, legitimately. The discriminator is what remains visible —
// a stuffed document still has a résumé on it, a scan has nothing.
const MIN_VISIBLE_CHARS_TO_JUDGE = 200;

// Below this, a finding is noise: PDF producers emit small invisible fragments
// for form fields, watermarks and accessibility artefacts. Keyword stuffing runs
// to hundreds of characters.
const MIN_HIDDEN_CHARS_TO_FLAG = 60;

// Only substantial blocks are cut from the text. A single hidden word may also
// appear legitimately in the visible résumé, and removing every occurrence would
// corrupt the copy we were paid to analyse.
const MIN_RUN_CHARS_TO_REDACT = 24;
// ...and a span has to be at least this many consecutive words before it is cut,
// so an incidental overlap of two or three common words is never enough.
const MIN_WORDS_TO_REDACT = 5;

// Fine print bottoms out around 5pt. Nothing legible is set below this, measured
// after the text matrix and the CTM have had their say.
const MIN_LEGIBLE_FONT_PT = 2.5;

// Anything this close to white is invisible on a white page.
const WHITE_LUMINANCE = 0.92;

// A shape dark enough to carry white text.
const DARK_LUMINANCE = 0.5;

const MAX_PAGES = 8;
const MAX_RUNS = 40;
const MAX_WORDS_PER_RUN = 300;

const EMPTY = Object.freeze({ flagged: false, chars: 0, redacted: 0, reasons: [] });

function luminance(hex) {
  if (typeof hex !== 'string' || !/^#[0-9a-f]{6}$/i.test(hex)) return null;
  const [r, g, b] = [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

const scaleOf = m =>
  Array.isArray(m) && m.length >= 4 ? Math.sqrt(Math.abs(m[0] * m[3] - m[1] * m[2])) : 1;

const countChars = s => s.replace(/\s+/g, '').length;

/**
 * pdfjs hands showText a mixed array: glyph objects carry `unicode`, bare
 * numbers are kerning adjustments. The other two show operators wrap the same
 * array behind leading spacing arguments, so find it rather than index into it.
 */
function glyphsToText(args) {
  const glyphs = Array.isArray(args) ? args.find(a => Array.isArray(a)) : null;
  if (!glyphs) return '';
  let out = '';
  for (const g of glyphs) {
    if (typeof g === 'number') { if (g < -100) out += ' '; continue; }
    if (g && typeof g.unicode === 'string') out += g.unicode;
  }
  return out;
}

let pdfjsPromise;
function loadPdfjs() {
  // pdfjs-dist v5 ships ESM only. Keep the specifier literal so Vercel's
  // dependency tracer follows it, and load once per process.
  if (!pdfjsPromise) pdfjsPromise = import('pdfjs-dist/legacy/build/pdf.mjs');
  return pdfjsPromise;
}

/**
 * Walk one page's operator list and split its text into visible and hidden runs.
 *
 * Text state (render mode, font) belongs to the graphics state: it survives
 * BT/ET and is saved and restored by q/Q. A document that sets `3 Tr` once and
 * never resets it hides everything that follows, which is why this tracks state
 * across the whole page rather than resetting per text object.
 */
function classifyPage(ops, OPS) {
  const paintsFill = new Set([OPS.fill, OPS.eoFill, OPS.fillStroke, OPS.eoFillStroke,
    OPS.closeFillStroke, OPS.closeEOFillStroke]);
  const paintsImage = new Set([OPS.paintImageXObject, OPS.paintInlineImageXObject,
    OPS.paintImageMaskXObject]);

  // Pass one: does this page carry anything white text could legitimately sit
  // on? Backgrounds are normally painted first, but not always, so decide over
  // the whole page before judging a single run.
  let backdrop = false;
  {
    let fill = '#000000';
    for (let i = 0; i < ops.fnArray.length && !backdrop; i++) {
      const fn = ops.fnArray[i];
      const args = ops.argsArray[i];
      if (fn === OPS.setFillRGBColor) { fill = args[0]; continue; }
      if (paintsImage.has(fn)) { backdrop = true; continue; }
      const painted = fn === OPS.constructPath ? args[0] : fn;
      if (paintsFill.has(painted)) {
        const l = luminance(fill);
        if (l !== null && l < DARK_LUMINANCE) backdrop = true;
      }
    }
  }

  const state = { mode: 0, fill: '#000000', size: 0, text: 1, ctm: 1 };
  const stack = [];
  const runs = [];
  let visible = '';
  let current = null;

  const flush = () => { if (current) { runs.push(current); current = null; } };

  for (let i = 0; i < ops.fnArray.length; i++) {
    const fn = ops.fnArray[i];
    const args = ops.argsArray[i];

    if (fn === OPS.save) { stack.push({ ...state }); continue; }
    if (fn === OPS.restore) { Object.assign(state, stack.pop() || state); flush(); continue; }
    if (fn === OPS.transform) { state.ctm *= scaleOf(args) || 1; continue; }
    if (fn === OPS.beginText) { state.text = 1; continue; }
    if (fn === OPS.setTextMatrix) { state.text = scaleOf(args) || 1; continue; }
    if (fn === OPS.setFont) { state.size = Math.abs(args[1]) || 0; continue; }
    if (fn === OPS.setTextRenderingMode) { state.mode = args[0]; flush(); continue; }
    if (fn === OPS.setFillRGBColor) { state.fill = args[0]; flush(); continue; }

    const shows = fn === OPS.showText || fn === OPS.nextLineShowText
      || fn === OPS.nextLineSetSpacingShowText;
    if (!shows) continue;

    const text = glyphsToText(args);
    if (!text.trim()) continue;

    // Mode 3 paints nothing; mode 7 only adds to the clip path. Modes 1 and 5
    // stroke without filling, so the fill colour says nothing about them.
    let reason = null;
    if (state.mode === 3 || state.mode === 7) {
      reason = 'invisible';
    } else if (state.size * state.text * state.ctm < MIN_LEGIBLE_FONT_PT) {
      reason = 'tiny';
    } else if (!backdrop && state.mode !== 1 && state.mode !== 5) {
      const l = luminance(state.fill);
      if (l !== null && l >= WHITE_LUMINANCE) reason = 'white';
    }

    if (!reason) { visible += text + ' '; flush(); continue; }
    if (current && current.reason === reason) current.text += text + ' ';
    else { flush(); current = { reason, text: text + ' ' }; }
  }
  flush();
  return { runs, visible };
}

async function scanPdf(buffer) {
  const pdfjs = await loadPdfjs();
  const doc = await pdfjs.getDocument({
    data: new Uint8Array(buffer),
    isEvalSupported: false,
    disableFontFace: true,
    useSystemFonts: false,
    // Nothing here is rendered, so pdfjs's warnings about missing standard font
    // data describe a job we are not doing. They would otherwise print once per
    // page of every upload. Errors still surface: they reject the promise.
    verbosity: 0,
  }).promise;
  try {
    const runs = [];
    let visibleChars = 0;
    const pages = Math.min(doc.numPages, MAX_PAGES);
    for (let n = 1; n <= pages; n++) {
      const page = await doc.getPage(n);
      try {
        const found = classifyPage(await page.getOperatorList(), pdfjs.OPS);
        runs.push(...found.runs);
        visibleChars += countChars(found.visible);
      } finally {
        page.cleanup();
      }
    }
    return { runs, visibleChars };
  } finally {
    await doc.destroy();
  }
}

// ── DOCX ──────────────────────────────────────────────────────────────────────
// w:r elements do not nest, so a non-greedy match over them is exact. Run
// properties live in the first w:rPr inside the run; the w:rPr that hangs off a
// paragraph's w:pPr describes the paragraph mark and is not a run.
const RUN_RE = /<w:r\b[^>]*>([\s\S]*?)<\/w:r>/g;
const RPR_RE = /<w:rPr\b[^>]*>([\s\S]*?)<\/w:rPr>/;
const TEXT_RE = /<w:t\b[^>]*>([\s\S]*?)<\/w:t>/g;
const SHADING_RE = /<w:shd\b[^>]*w:fill="([0-9A-Fa-f]{6})"/g;

const decodeXml = s => s
  .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
  .replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d))
  .replace(/&amp;/g, '&');

/** `<w:vanish/>`, `<w:vanish w:val="1"/>` and `<w:vanish w:val="true"/>` all hide. */
const toggledOn = (props, tag) => {
  const m = new RegExp(`<w:${tag}\\b([^>]*)/?>`).exec(props);
  if (!m) return false;
  const val = /w:val="([^"]*)"/.exec(m[1]);
  return !val || !/^(0|false|off)$/i.test(val[1]);
};

function scanDocxXml(xml) {
  // Same stance as the PDF backdrop: if the document shades anything darkly,
  // white text may be sitting on it legitimately, so drop colour findings.
  let shaded = false;
  for (const m of xml.matchAll(SHADING_RE)) {
    const l = luminance(`#${m[1]}`);
    if (l !== null && l < DARK_LUMINANCE) { shaded = true; break; }
  }

  const runs = [];
  let visibleChars = 0;
  for (const match of xml.matchAll(RUN_RE)) {
    const body = match[1];
    let text = '';
    for (const t of body.matchAll(TEXT_RE)) text += decodeXml(t[1]);
    if (!text.trim()) continue;

    const props = RPR_RE.exec(body)?.[1] || '';
    let reason = null;
    if (toggledOn(props, 'vanish')) {
      reason = 'invisible';
    } else {
      // w:sz is in half-points, so 4 is 2pt.
      const size = /<w:sz\b[^>]*w:val="(\d+)"/.exec(props);
      const color = /<w:color\b[^>]*w:val="([0-9A-Fa-f]{6})"/.exec(props);
      if (size && Number(size[1]) / 2 < MIN_LEGIBLE_FONT_PT) reason = 'tiny';
      else if (!shaded && color && (luminance(`#${color[1]}`) ?? 0) >= WHITE_LUMINANCE) reason = 'white';
    }

    if (reason) runs.push({ reason, text: text + ' ' });
    else visibleChars += countChars(text);
  }
  return { runs, visibleChars };
}

async function scanDocx(buffer) {
  const JSZip = require('jszip');
  const zip = await JSZip.loadAsync(buffer);
  const doc = zip.file('word/document.xml');
  if (!doc) return { runs: [], visibleChars: 0 };
  return scanDocxXml(await doc.async('string'));
}

// ── Redaction ─────────────────────────────────────────────────────────────────
const escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const spanRe = words => new RegExp(words.map(escapeRe).join('\\s+'), 'gi');

/**
 * Cut the hidden blocks out of the extracted text.
 *
 * Both sides describe the same glyphs, but they do not line up character for
 * character: each extractor inserts its own line breaks, and a hidden run
 * reconstructed from the operator list can pick up neighbouring text that the
 * text layer laid out somewhere else. Matching the whole run and giving up when
 * it fails left entire stuffing blocks in place.
 *
 * So walk the run instead. From each position, take the shortest span worth
 * cutting and extend it word by word for as long as the text still contains it,
 * then remove the longest span that matched and carry on after it. That removes
 * whatever part of the hidden block is actually present without depending on the
 * run and the text agreeing at the edges.
 *
 * Every pattern is a run of literals joined by one `\s+`, so there is no nested
 * quantifier here to backtrack over.
 *
 * One accepted imprecision: if the hidden block is a copy of text that is also
 * visible, both copies go. We cannot tell them apart from the text alone, and
 * cutting both is the safer side — the finding is still reported either way.
 */
function redactHiddenRuns(text, runs) {
  let out = text;
  let removed = 0;
  const seen = new Set();
  const ordered = [...runs].sort((a, b) => b.text.length - a.text.length).slice(0, MAX_RUNS);

  for (const run of ordered) {
    const words = run.text.trim().split(/\s+/).filter(Boolean).slice(0, MAX_WORDS_PER_RUN);
    const key = words.join(' ').toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    if (countChars(key) < MIN_RUN_CHARS_TO_REDACT) continue;

    let i = 0;
    while (i + MIN_WORDS_TO_REDACT <= words.length) {
      let end = i + MIN_WORDS_TO_REDACT;
      if (!spanRe(words.slice(i, end)).test(out)) { i++; continue; }
      while (end < words.length && spanRe(words.slice(i, end + 1)).test(out)) end++;
      const span = words.slice(i, end);
      if (countChars(span.join(' ')) >= MIN_RUN_CHARS_TO_REDACT) {
        out = out.replace(spanRe(span), match => { removed += match.length; return ' '; });
      }
      i = end;
    }
  }
  return { text: out.replace(/[ \t]{2,}/g, ' ').trim(), removed };
}

/**
 * Judge a scan. Returns EMPTY unless there is enough visible résumé to be sure
 * the hidden text is an addition rather than the whole document.
 */
function assess(scan) {
  const runs = scan.runs.filter(r => r.text.trim());
  const chars = runs.reduce((n, r) => n + countChars(r.text), 0);
  if (scan.visibleChars < MIN_VISIBLE_CHARS_TO_JUDGE) return EMPTY;
  if (chars < MIN_HIDDEN_CHARS_TO_FLAG) return EMPTY;
  return {
    flagged: true,
    chars,
    redacted: 0,
    reasons: [...new Set(runs.map(r => r.reason))].sort(),
    runs,
  };
}

const PDF_MIME = 'application/pdf';
const DOCX_MIME = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';

/**
 * Find hidden text and cut it out of `text`.
 *
 * Never throws and never rejects: on any failure the caller gets the text it
 * passed in and a report of "nothing found". A detection bug must not cost
 * someone the analysis they paid for.
 */
function withDeadline(promise, budgetMs) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('hidden-text scan timed out')), budgetMs);
    }),
  ]).finally(() => clearTimeout(timer));
}

async function stripHiddenText(text, buffer, mimetype, budgetMs = 5000, scanner) {
  const give = reason => ({ text, hidden: EMPTY, skipped: reason });
  try {
    if (!(budgetMs > 0)) return give('no-budget');
    // `scanner` exists so a test can hold the scan open and prove the deadline
    // actually protects the caller. Production never passes it.
    const scan = scanner ? scanner(buffer, mimetype)
      : mimetype === PDF_MIME ? scanPdf(buffer)
        : mimetype === DOCX_MIME ? scanDocx(buffer)
          : null;
    if (!scan) return give('unsupported');

    const verdict = assess(await withDeadline(scan, budgetMs));
    if (!verdict.flagged) return give(null);

    const { text: cleaned, removed } = redactHiddenRuns(text, verdict.runs);
    const { runs, ...hidden } = verdict;
    return { text: cleaned, hidden: { ...hidden, redacted: removed }, skipped: null };
  } catch (err) {
    return { ...give('error'), error: err };
  }
}

module.exports = {
  stripHiddenText,
  __test: {
    assess, classifyPage, luminance, redactHiddenRuns, scanDocxXml, scanPdf, scanDocx, withDeadline,
    MIN_HIDDEN_CHARS_TO_FLAG, MIN_LEGIBLE_FONT_PT, MIN_VISIBLE_CHARS_TO_JUDGE,
  },
};
