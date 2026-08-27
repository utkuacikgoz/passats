/**
 * Hidden-text detection.
 *
 * These assertions run against real files built here, not against mocks of what
 * a parser might return, because the whole point is that render mode and fill
 * colour do not survive into extracted text. Every fixture is a document that
 * pdfjs and mammoth actually parse.
 *
 * The negative cases carry as much weight as the positive ones. Telling a paying
 * customer their clean CV is stuffed with invisible keywords is a worse failure
 * than missing a cheat, so white text on a dark sidebar, a 1pt font scaled up by
 * the text matrix, and a scanned page's OCR layer all have to come back clean.
 *
 * Usage: node --test test/hidden-text.test.js
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { stripHiddenText, __test } = require('../lib/hidden-text');

const PDF_MIME = 'application/pdf';
const DOCX_MIME = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';

// Enough visible résumé to clear MIN_VISIBLE_CHARS_TO_JUDGE, so the scan is
// judging an addition to a document rather than a scan of one.
const RESUME = 'Dani Okonkwo dani@example.com 555 0100 Software Engineer. '
  + 'Built and shipped payment services at Revolut across three teams. '
  + 'Migrated fourteen services to a new platform and cut release time from five days to one. '
  + 'Led the CI and CD rollout. Education BSc Computer Science University of Leeds 2016.';

const STUFFING = 'Kubernetes Terraform Rust Golang Machine Learning Kubernetes Terraform '
  + 'Distributed Systems Staff Engineer Principal Engineer PhD Stanford MIT';

/** Minimal single-page PDF with a Helvetica font and one content stream. */
function pdf(body) {
  const objs = [
    null,
    '<</Type/Catalog/Pages 2 0 R>>',
    '<</Type/Pages/Kids[3 0 R]/Count 1>>',
    '<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>',
    `<</Length ${body.length}>>\nstream\n${body}\nendstream`,
    '<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>',
  ];
  let out = '%PDF-1.4\n';
  const offsets = [];
  for (let i = 1; i < objs.length; i++) {
    offsets[i] = out.length;
    out += `${i} 0 obj\n${objs[i]}\nendobj\n`;
  }
  const xref = out.length;
  out += `xref\n0 ${objs.length}\n0000000000 65535 f \n`;
  for (let i = 1; i < objs.length; i++) out += String(offsets[i]).padStart(10, '0') + ' 00000 n \n';
  out += `trailer<</Size ${objs.length}/Root 1 0 R>>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(out, 'latin1');
}

/** Lay a string out as one Tj per line so the fixtures stay readable. */
const show = (text, y, prefix = '') =>
  `BT /F1 11 Tf 40 ${y} Td ${prefix}(${text.replace(/[()\\]/g, '')}) Tj ET`;

const visibleResume = () => RESUME.match(/.{1,60}(\s|$)/g)
  .map((line, i) => show(line.trim(), 720 - i * 14))
  .join('\n');

// Store-only ZIP writer — enough for a valid DOCX without a build dependency.
function zip(files) {
  const table = (() => {
    const t = [];
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
    return t;
  })();
  const crc = b => { let c = 0xFFFFFFFF; for (const x of b) c = table[(c ^ x) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; };
  const locals = []; const centrals = []; let off = 0;
  for (const [name, content] of files) {
    const n = Buffer.from(name); const d = Buffer.from(content); const c = crc(d);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4);
    lh.writeUInt32LE(c, 14); lh.writeUInt32LE(d.length, 18); lh.writeUInt32LE(d.length, 22); lh.writeUInt16LE(n.length, 26);
    locals.push(lh, n, d);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6);
    ch.writeUInt32LE(c, 16); ch.writeUInt32LE(d.length, 20); ch.writeUInt32LE(d.length, 24);
    ch.writeUInt16LE(n.length, 28); ch.writeUInt32LE(off, 42);
    centrals.push(ch, n);
    off += lh.length + n.length + d.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, end]);
}

const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');
const run = (text, props = '') =>
  `<w:r>${props ? `<w:rPr>${props}</w:rPr>` : ''}<w:t xml:space="preserve">${esc(text)}</w:t></w:r>`;

function docx(bodyRuns, extraParagraphProps = '') {
  const doc = '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
    + `<w:p>${extraParagraphProps}${bodyRuns}</w:p></w:body></w:document>`;
  const ct = '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>';
  const root = '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>';
  return zip([['[Content_Types].xml', ct], ['_rels/.rels', root], ['word/document.xml', doc]]);
}

/** What extractText would hand us: the résumé with the hidden block appended. */
const extractedWith = block => `${RESUME} ${block}`;

describe('PDF — text the page never paints', () => {
  it('finds and removes render mode 3', async () => {
    const buffer = pdf([visibleResume(), show(STUFFING, 300, '3 Tr ')].join('\n'));
    const out = await stripHiddenText(extractedWith(STUFFING), buffer, PDF_MIME);
    assert.equal(out.hidden.flagged, true, 'invisible keyword block was not detected');
    assert.deepEqual(out.hidden.reasons, ['invisible']);
    assert.doesNotMatch(out.text, /Terraform/, 'the hidden block still reaches the model');
    assert.match(out.text, /Revolut/, 'the real CV was damaged');
    assert.ok(out.hidden.redacted > 0);
  });

  it('finds text left invisible after the text object that set the mode', async () => {
    // Tr is graphics state, not text-object state: it survives ET. Setting it
    // once and never resetting hides everything that follows, which a detector
    // that resets per BT would miss entirely.
    const buffer = pdf([
      visibleResume(),
      show('Switching now', 300, '3 Tr '),
      show(STUFFING, 286),
    ].join('\n'));
    const out = await stripHiddenText(extractedWith(STUFFING), buffer, PDF_MIME);
    assert.equal(out.hidden.flagged, true);
    assert.doesNotMatch(out.text, /Terraform/);
  });

  it('finds white on white', async () => {
    const buffer = pdf([visibleResume(), show(STUFFING, 300, '1 1 1 rg ')].join('\n'));
    const out = await stripHiddenText(extractedWith(STUFFING), buffer, PDF_MIME);
    assert.equal(out.hidden.flagged, true, 'white on white was not detected');
    assert.deepEqual(out.hidden.reasons, ['white']);
    assert.doesNotMatch(out.text, /Terraform/);
  });

  it('finds white set through a colour space that is not RGB', async () => {
    // `1 g` and `0 0 0 0 k` are the same white. pdfjs normalises both, and a
    // detector that only watched `rg` would miss the other two spellings.
    for (const op of ['1 g ', '0 0 0 0 k ']) {
      const buffer = pdf([visibleResume(), show(STUFFING, 300, op)].join('\n'));
      const out = await stripHiddenText(extractedWith(STUFFING), buffer, PDF_MIME);
      assert.equal(out.hidden.flagged, true, `${op} was not detected as white`);
    }
  });

  it('finds a font too small to read', async () => {
    const buffer = pdf([visibleResume(), `BT /F1 1 Tf 40 300 Td (${STUFFING}) Tj ET`].join('\n'));
    const out = await stripHiddenText(extractedWith(STUFFING), buffer, PDF_MIME);
    assert.equal(out.hidden.flagged, true, '1pt text was not detected');
    assert.deepEqual(out.hidden.reasons, ['tiny']);
  });
});

describe('PDF — documents that must not be accused', () => {
  it('leaves white text on a dark sidebar alone', async () => {
    // A designer résumé with a dark column and white text in it. Flagging this
    // would call a paying customer a cheat over a template choice.
    const buffer = pdf([
      '0.1 0.1 0.12 rg 0 0 200 792 re f',
      show('Dani Okonkwo', 720, '1 1 1 rg '),
      show('Software Engineer London', 706, '1 1 1 rg '),
      visibleResume(),
    ].join('\n'));
    const out = await stripHiddenText(extractedWith(''), buffer, PDF_MIME);
    assert.equal(out.hidden.flagged, false, 'white text on a dark panel was called hidden');
    assert.match(out.text, /Revolut/);
  });

  it('leaves a 1pt font scaled up by the text matrix alone', async () => {
    // A very common way to typeset a PDF: set the font at 1 unit and carry the
    // real size in Tm. Judging Tf alone would flag most PDFs in the world.
    const body = RESUME.match(/.{1,60}(\s|$)/g)
      .map((line, i) => `BT /F1 1 Tf 11 0 0 11 40 ${720 - i * 14} Tm (${line.trim()}) Tj ET`)
      .join('\n');
    const out = await stripHiddenText(RESUME, pdf(body), PDF_MIME);
    assert.equal(out.hidden.flagged, false, 'matrix-scaled text was judged on its raw font size');
  });

  it('leaves a scanned page with an OCR layer alone', async () => {
    // Every character of a searchable scan is mode 3 by design. There is no
    // visible text to compare against, which is exactly what tells them apart.
    const body = RESUME.match(/.{1,60}(\s|$)/g)
      .map((line, i) => show(line.trim(), 720 - i * 14, '3 Tr '))
      .join('\n');
    const out = await stripHiddenText(RESUME, pdf(body), PDF_MIME);
    assert.equal(out.hidden.flagged, false, 'an OCR text layer was called keyword stuffing');
    assert.equal(out.text, RESUME, 'the OCR layer was redacted away');
  });

  it('ignores a hidden fragment too short to be stuffing', async () => {
    const buffer = pdf([visibleResume(), show('v2.1', 300, '3 Tr ')].join('\n'));
    const out = await stripHiddenText(extractedWith('v2.1'), buffer, PDF_MIME);
    assert.equal(out.hidden.flagged, false, 'a producer artefact was reported as hidden text');
  });
});

describe('DOCX — hidden runs', () => {
  it('finds w:vanish', async () => {
    const buffer = docx(run(RESUME) + run(STUFFING, '<w:vanish/>'));
    const out = await stripHiddenText(extractedWith(STUFFING), buffer, DOCX_MIME);
    assert.equal(out.hidden.flagged, true, 'w:vanish was not detected');
    assert.deepEqual(out.hidden.reasons, ['invisible']);
    assert.doesNotMatch(out.text, /Terraform/);
  });

  it('finds white text and text set at a fraction of a point', async () => {
    for (const [props, reason] of [
      ['<w:color w:val="FFFFFF"/>', 'white'],
      ['<w:sz w:val="2"/>', 'tiny'],
    ]) {
      const buffer = docx(run(RESUME) + run(STUFFING, props));
      const out = await stripHiddenText(extractedWith(STUFFING), buffer, DOCX_MIME);
      assert.equal(out.hidden.flagged, true, `${props} was not detected`);
      assert.deepEqual(out.hidden.reasons, [reason]);
    }
  });

  it('reads w:vanish switched off as visible', async () => {
    const buffer = docx(run(RESUME) + run(STUFFING, '<w:vanish w:val="0"/>'));
    const out = await stripHiddenText(extractedWith(STUFFING), buffer, DOCX_MIME);
    assert.equal(out.hidden.flagged, false, 'a disabled toggle was read as enabled');
  });

  it('leaves white text on dark shading alone', async () => {
    const buffer = docx(
      run(RESUME) + run('Dani Okonkwo', '<w:color w:val="FFFFFF"/>'),
      '<w:pPr><w:shd w:val="clear" w:fill="1A1A1F"/></w:pPr>',
    );
    const out = await stripHiddenText(extractedWith(''), buffer, DOCX_MIME);
    assert.equal(out.hidden.flagged, false, 'white text on a shaded banner was called hidden');
  });
});

describe('failure is never the customer\'s problem', () => {
  it('returns the text untouched when the file cannot be parsed', async () => {
    const out = await stripHiddenText(RESUME, Buffer.from('not a pdf at all'), PDF_MIME);
    assert.equal(out.text, RESUME);
    assert.equal(out.hidden.flagged, false);
    assert.ok(out.error, 'the failure was swallowed without a trace to log');
  });

  it('does not start a scan it has no budget for', async () => {
    const buffer = pdf([visibleResume(), show(STUFFING, 300, '3 Tr ')].join('\n'));
    const out = await stripHiddenText(extractedWith(STUFFING), buffer, PDF_MIME, 0);
    assert.equal(out.text, extractedWith(STUFFING), 'a scan ran on a spent budget');
    assert.equal(out.skipped, 'no-budget');
  });

  it('gives up on a scan that never finishes', async () => {
    // Asserted against a promise that genuinely never settles. Racing a real
    // scan of a small fixture proves nothing: it wins, and the test passes for
    // the wrong reason.
    await assert.rejects(
      __test.withDeadline(new Promise(() => {}), 20),
      /timed out/,
    );
  });

  it('a scan that times out mid-document leaves the text alone', async () => {
    const buffer = pdf([visibleResume(), show(STUFFING, 300, '3 Tr ')].join('\n'));
    const slow = new Promise(() => {});
    const out = await stripHiddenText(extractedWith(STUFFING), buffer, PDF_MIME, 20, () => slow);
    assert.equal(out.text, extractedWith(STUFFING), 'a timed-out scan damaged the text');
    assert.equal(out.hidden.flagged, false);
  });

  it('leaves a file type it does not understand alone', async () => {
    const out = await stripHiddenText(RESUME, Buffer.from('x'), 'text/plain');
    assert.equal(out.text, RESUME);
    assert.equal(out.skipped, 'unsupported');
  });
});

describe('redaction', () => {
  it('does not remove a word that also appears in the visible CV', async () => {
    // "Git" hidden and "Git" visible are the same three characters. Only blocks
    // large enough to be stuffing are cut, so the real CV survives intact.
    const { text, removed } = __test.redactHiddenRuns('I use Git daily at Revolut.', [{ reason: 'invisible', text: 'Git ' }]);
    assert.equal(removed, 0);
    assert.match(text, /Git/);
  });

  it('matches across the line breaks the extractor inserted', async () => {
    const { text } = __test.redactHiddenRuns(
      `${RESUME}\nKubernetes Terraform\nRust Golang Machine Learning`,
      [{ reason: 'invisible', text: 'Kubernetes Terraform Rust Golang Machine Learning ' }],
    );
    assert.doesNotMatch(text, /Terraform/, 'a run split across lines was not matched');
  });
});
