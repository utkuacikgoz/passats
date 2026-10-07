/**
 * The free parse preview.
 *
 * This is the only endpoint on the site that does real work for an anonymous
 * caller, so the assertions that matter most are not about the happy path. They
 * are that it cannot be turned into free compute, that it cannot be used to
 * check whether hidden keywords survived extraction, and that it never keeps the
 * file it was given.
 *
 * Usage: node --test test/parse-preview.test.js
 */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.DEV_MODE = 'true';
delete process.env.VERCEL;

// multer writes uploads to os.tmpdir(), which POSIX resolves from TMPDIR at call
// time. Giving this suite its own directory makes the "nothing is kept" check
// exact: node --test runs suites in parallel, and scanning the shared tmp meant
// asserting against files other suites were uploading at the same moment.
const UPLOAD_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'passats-preview-tmp-'));
process.env.TMPDIR = UPLOAD_DIR;

const app = require('../server');

let server;
let origin;

before(async () => {
  await new Promise(resolve => { server = app.listen(0, resolve); });
  origin = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { await new Promise(resolve => server.close(resolve)); });

function pdf(body, mediaBox = '0 0 612 792') {
  const objs = [
    null,
    '<</Type/Catalog/Pages 2 0 R>>',
    '<</Type/Pages/Kids[3 0 R]/Count 1>>',
    `<</Type/Page/Parent 2 0 R/MediaBox[${mediaBox}]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>`,
    `<</Length ${body.length}>>\nstream\n${body}\nendstream`,
    '<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>',
  ];
  let out = '%PDF-1.4\n';
  const offsets = [];
  for (let i = 1; i < objs.length; i++) { offsets[i] = out.length; out += `${i} 0 obj\n${objs[i]}\nendobj\n`; }
  const xref = out.length;
  out += `xref\n0 ${objs.length}\n0000000000 65535 f \n`;
  for (let i = 1; i < objs.length; i++) out += String(offsets[i]).padStart(10, '0') + ' 00000 n \n';
  out += `trailer<</Size ${objs.length}/Root 1 0 R>>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(out, 'latin1');
}

const CV = [
  'Dani Okonkwo dani@example.com 555 0100 Software Engineer',
  'Built and shipped payment services at Revolut across three teams',
  'Migrated fourteen services and cut release time from five days to one',
  'Led the CI and CD rollout. BSc Computer Science University of Leeds 2016',
];
const STUFFING = 'Kubernetes Terraform Rust Golang Machine Learning Staff Engineer PhD Stanford MIT';
const lines = extra => [
  ...CV.map((line, i) => `BT /F1 11 Tf 40 ${740 - i * 16} Td (${line}) Tj ET`),
  ...extra,
].join('\n');

// The endpoint is rate limited per IP, tightly, which is the point of it. Each
// test gets its own caller so one test cannot spend another's allowance; the
// limit itself is asserted below, from a single IP, on purpose.
let caller = 0;
const nextIp = () => `203.0.113.${++caller}`;

async function preview(buffer, name = 'cv.pdf', type = 'application/pdf', ip = nextIp()) {
  const body = new FormData();
  body.append('cv', new Blob([buffer], { type }), name);
  const response = await fetch(`${origin}/api/parse-preview`, {
    method: 'POST',
    headers: { Origin: origin, 'x-vercel-forwarded-for': ip },
    body,
  });
  return { status: response.status, json: await response.json().catch(() => ({})) };
}

// checkOrigin() short-circuits in dev mode, and every suite but payment.test.js
// boots in dev. The cross-origin rejection for this endpoint is asserted there,
// where the production branch actually runs.
describe('the free parse preview', () => {
  it('returns the text an ATS would read, and no analysis', async () => {
    const { status, json } = await preview(pdf(lines([])));
    assert.equal(status, 200);
    assert.match(json.text, /Revolut/);
    assert.equal(json.chars, json.text.length);
    assert.equal(json.truncated, false);
    // The whole point of free is that it costs a parse. If any of these ever
    // appear here, the paid product has been given away.
    for (const key of ['overallScore', 'metrics', 'topFixes', 'keywordsMissing', 'verdict']) {
      assert.equal(json[key], undefined, `${key} must not be in a free response`);
    }
  });

  it('needs no token, unlike the paid endpoint', async () => {
    const paid = await fetch(`${origin}/api/analyze`, { method: 'POST', headers: { Origin: origin } });
    assert.equal(paid.status, 401, 'the paid endpoint stopped requiring a token');
    const { status } = await preview(pdf(lines([])));
    assert.equal(status, 200, 'the free endpoint should not require one');
  });

  it('reports hidden text without ever echoing it back', async () => {
    // Reporting the finding is useful. Returning the text would make this a tool
    // for checking that your keyword stuffing survived extraction.
    const buffer = pdf(lines([`BT /F1 11 Tf 40 300 Td 1 1 1 rg (${STUFFING}) Tj ET`]));
    const { status, json } = await preview(buffer);
    assert.equal(status, 200);
    assert.equal(json.hidden.flagged, true);
    assert.deepEqual(json.hidden.reasons, ['white']);
    assert.doesNotMatch(json.text, /Terraform|Stanford/, 'the hidden block was handed back to the uploader');
  });

  it('says nothing about hidden text on a clean file', async () => {
    const { json } = await preview(pdf(lines([])));
    assert.deepEqual(json.hidden, { flagged: false });
  });

  it('rejects a file type an ATS could not read either', async () => {
    const { status, json } = await preview(Buffer.from('just some notes'), 'notes.txt', 'text/plain');
    assert.equal(status, 400);
    assert.match(json.error, /PDF or DOCX/i);
  });

  it('rejects a file whose first bytes do not match its type', async () => {
    const { status, json } = await preview(Buffer.from('just text, renamed'), 'fake.pdf', 'application/pdf');
    assert.equal(status, 400);
    assert.match(json.error, /does not match/i);
  });

  it('explains a corrupt file instead of failing at the customer', async () => {
    // Passes the magic-byte check and then falls apart in the parser. This is
    // ordinary input for a free tool, so it must not be a 500: a visitor whose
    // CV builder truncated the export learns something real here.
    const { status, json } = await preview(Buffer.from('%PDF-1.4 and then nothing valid'), 'broken.pdf');
    assert.equal(status, 422, 'a corrupt upload was reported as a server error');
    assert.match(json.error, /could not read that file/i);
  });

  it('explains an image-only PDF rather than failing at the customer', async () => {
    const { status, json } = await preview(pdf('BT /F1 11 Tf 40 700 Td (Hi) Tj ET'));
    assert.equal(status, 422);
    assert.match(json.error, /scan or an image/i);
  });

  it('cuts off a caller who keeps sending files', async () => {
    // This endpoint does real work for anyone who asks, so the rate limit is the
    // only thing between it and someone looping a 5MB PDF through it.
    const ip = nextIp();
    const file = pdf(lines([]));
    let sawLimit = false;
    for (let attempt = 0; attempt < 12 && !sawLimit; attempt++) {
      const { status } = await preview(file, 'cv.pdf', 'application/pdf', ip);
      if (status === 429) sawLimit = true;
    }
    assert.ok(sawLimit, 'the free endpoint never rate limited a repeat caller');
  });

  it('keeps nothing on disk', async () => {
    // Nothing stored is a promise the privacy page makes, and this endpoint takes
    // files from anyone. UPLOAD_DIR is private to this suite, so anything left in
    // it came from the request below and nowhere else.
    assert.deepEqual(fs.readdirSync(UPLOAD_DIR), [], 'the suite started with a dirty upload directory');
    const { status } = await preview(pdf(lines([])));
    assert.equal(status, 200);
    assert.deepEqual(
      fs.readdirSync(UPLOAD_DIR), [],
      'the uploaded file was left on disk after the response',
    );
  });

  it('keeps nothing on disk when the file cannot be read either', async () => {
    // The cleanup runs in a finally, and the error paths are where a leak would
    // actually happen: they return early from several different places.
    await preview(Buffer.from('%PDF-1.4 and then nothing valid'), 'broken.pdf');
    assert.deepEqual(fs.readdirSync(UPLOAD_DIR), [], 'a rejected upload was left on disk');
  });
});

describe('page one beside the text', () => {
  const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

  it('returns page one of a PDF as a PNG, beside the text', async () => {
    const { status, json } = await preview(pdf(lines([])));
    assert.equal(status, 200);
    assert.ok(json.page, 'no page image for an ordinary PDF');
    assert.match(json.page.image, /^data:image\/png;base64,/);
    const bytes = Buffer.from(json.page.image.split(',')[1], 'base64');
    assert.deepEqual(bytes.subarray(0, 8), PNG, 'not actually a PNG');
    assert.equal(json.page.width, 640);
    assert.ok(Math.abs(json.page.height / json.page.width - 792 / 612) < 0.01, 'page aspect lost');
    assert.ok(json.page.image.length < 800 * 1024);
  });

  it('skips a page no resume has, before allocating a canvas for it', async () => {
    // 100 x 14,400pt at 640px wide would be a canvas of hundreds of megabytes.
    // The text still comes back; only the picture is dropped.
    const { status, json } = await preview(pdf(lines([]), '0 0 100 14400'));
    assert.equal(status, 200);
    assert.equal(json.page, null);
    assert.ok(typeof json.text === 'string');
    // And for the right reason: refused on shape, not rendered and then dropped.
    const direct = await app.__test.renderFirstPage(pdf(lines([]), '0 0 100 14400'));
    assert.equal(direct.skipped, 'page_shape');
  });

  it('renders nothing for a DOCX, which has no fixed page to show', async () => {
    const JSZip = require('jszip');
    const zip = new JSZip();
    zip.file('[Content_Types].xml', '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>');
    zip.file('_rels/.rels', '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>');
    zip.file('word/document.xml', '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
      + CV.map(line => `<w:p><w:r><w:t>${line}</w:t></w:r></w:p>`).join('') + '</w:body></w:document>');
    const buffer = await zip.generateAsync({ type: 'nodebuffer' });
    const { status, json } = await preview(buffer, 'cv.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    assert.equal(status, 200);
    assert.match(json.text, /Revolut/);
    assert.equal(json.page, null);
  });

  it('the page script only ever shows a PNG data URL the server rendered', () => {
    const script = fs.readFileSync(path.join(__dirname, '..', 'public', 'parse-preview.js'), 'utf8');
    assert.match(script, /page\.image\.indexOf\('data:image\/png;base64,'\) === 0/);
  });
});

describe('the page itself', () => {
  it('is served, indexable and canonical', async () => {
    const response = await fetch(`${origin}/ats-parse-preview`);
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.match(html, /<link rel="canonical" href="https:\/\/passats\.pro\/ats-parse-preview">/);
    assert.match(html, /name="robots" content="index, follow"/);
    assert.match(html, /"@type": "WebApplication"/);
  });

  it('carries no inline script, so no CSP hash can go stale on it', async () => {
    // The policy has no 'unsafe-inline'. An inline block here would have to be
    // threaded through sync-csp-hashes.js, which only reads views/index.html —
    // the page would break silently the first time someone edited it.
    const html = await (await fetch(`${origin}/ats-parse-preview`)).text();
    const inline = [...html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)]
      .filter(([, attrs, body]) => !attrs.includes('application/ld+json') && body.trim())
      // The Vercel analytics shim is hash-allowlisted already and is shared with
      // every other page on the site.
      .filter(([, , body]) => !body.includes('window.va'));
    assert.deepEqual(inline.map(m => m[2].trim().slice(0, 40)), []);
    assert.match(html, /<script src="\/parse-preview\.js" defer><\/script>/);
  });

  it('is reachable from the sitemap and from the guides', async () => {
    const sitemap = await (await fetch(`${origin}/sitemap.xml`)).text();
    assert.match(sitemap, /<loc>https:\/\/passats\.pro\/ats-parse-preview<\/loc>/);
    const guide = await (await fetch(`${origin}/ats-parsing-errors`)).text();
    assert.match(guide, /href="\/ats-parse-preview"/, 'the tool is an orphan page');
  });

  it('ships its script as a static file the CSP already allows', async () => {
    const response = await fetch(`${origin}/parse-preview.js`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type') || '', /javascript/);
    // textContent, not innerHTML: the text came out of someone else's file.
    const source = await response.text();
    assert.match(source, /output\.textContent = data\.text/);
    // Actual use, not the word: the file explains in a comment why it does not
    // do this, and matching the bare word failed on that comment.
    assert.doesNotMatch(
      source,
      /\.innerHTML\s*=|insertAdjacentHTML|document\.write/,
      'uploaded text must never be written as markup',
    );
  });
});
