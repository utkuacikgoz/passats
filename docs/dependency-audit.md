# Dependency audit — 2026-09-19

`npm audit` result after this update: **0 vulnerabilities**, production and dev.

## What was updated

Dependabot's minor-and-patch group (PR #45), applied directly rather than
merged: the PR was based on a `main` that had since moved, GitHub reported it
`dirty`, and Dependabot closed it.

| Package | From | To |
|---|---|---|
| `@anthropic-ai/sdk` | 0.120.0 | 0.125.0 |
| `@napi-rs/canvas` | 1.0.7 | 1.0.9 |
| `@upstash/redis` | 1.38.2 | 1.38.4 |
| `jszip` | 3.10.1 | 3.10.2 |
| `mammoth` | 1.12.1 | 1.12.3 |
| `multer` | 2.2.0 | 2.4.0 |
| `posthog-node` | 5.50.0 | 5.52.4 |
| `stripe` | 22.5.0 | 22.6.2 |
| `playwright` (dev) | 1.62.1 | 1.63.0 |

## Vulnerabilities closed

Both were transitive, both predate this update, and both were fixed by
lockfile-only resolution — no manifest change, nothing pinned, nothing
overridden.

### @xmldom/xmldom 0.8.13 → 0.8.15 — high

Reached through `mammoth`, which is the DOCX parser. This one mattered more
than its "transitive" label suggests: every uploaded .docx is attacker-supplied
XML, and it reaches this parser on two routes, one of which
(`/api/parse-preview`) takes no token at all. The advisories include
quadratic-time parsing, quadratic-memory consumption and an end-tag regex
ReDoS — CPU exhaustion against a function with a 60-second ceiling, where the
kill lands outside the try/catch.

### qs 6.15.2 → 6.16.0 — moderate

Reached through `express` and `body-parser`. An array-limit bypass and a
denial of service via attacker-controlled `isBuffer`.

## What was NOT taken

**PR #43, `pdfjs-dist` 5.4.296 → 6.2.108.** Held deliberately, not overlooked:

- The version is pinned exactly to match what `pdf-parse@2.4.5` resolves.
  Bumping only the direct dependency does not move `pdf-parse`; npm keeps its
  nested 5.4.296 as well, so the bundle would carry two copies of pdfjs and the
  hidden-text scanner would run a different version from the text extractor.
- `lib/hidden-text.js` reads pdfjs's operator list directly — `getOperatorList`,
  `OPS`, the `setTextRenderingMode` and `setFillRGBColor` opcodes. That is the
  code keeping keyword stuffing out of the score, and a major bump is exactly
  where those internals move.

Taking it means bumping `pdf-parse` in step and re-verifying the extraction and
hidden-text suites against real PDFs, not just letting the tests pass.

## How this was verified

- 230 of 233 node tests pass. The three failures are in `test/domain.test.js`
  and are an artifact of the verification worktree: the test runs a patched copy
  of `scripts/sync-domain.js` out of the system temp directory, and that script
  resolves its paths from `__dirname`, so the result depends on where the repo
  sits relative to `os.tmpdir()`. Confirmed environmental by reverting
  `package.json` to `main` in the same worktree and watching the same three
  fail. They pass in a normal checkout. The test is fragile and worth fixing
  separately.
- All 19 browser tests pass.
- The DOCX path was exercised specifically after the xmldom bump:
  `injection`, `hidden-text` and `parse-preview` — 48 tests, all passing.
