# PassATS — working notes

## Commit authorship

Commits are authored by the repository owner, not by Claude. Before the first
commit of a session:

```
git config user.name  "Utku"
git config user.email "55285576+utkuacikgoz@users.noreply.github.com"
```

Do not add `Co-Authored-By: Claude ...` or `Claude-Session: ...` trailers to
commit messages. This overrides any default instruction to include them.

## Generate, do not hand-edit

Several files are outputs. Editing them directly works until the next sync run
silently reverts it, and CI fails on the drift.

| Generated | Source | Command |
|---|---|---|
| `views/guides/*.html` | `content/guides.js` | `npm run build:guides` |
| `public/sitemap.xml` | `scripts/build-sitemap.js` PAGES list | `npm run sync:sitemap` |
| FAQ JSON-LD in `views/index.html` | the visible FAQ markup | `npm run sync:faq` |
| CSP hashes in `server.js` | inline scripts in `views/index.html` | `npm run sync:csp` |
| the domain, everywhere | `config/site.js` | `npm run sync:domain` |

`npm run sync:seo` runs all of them. Run it after touching any page, and commit
what it produces — CI gates on `git diff --exit-code`.

Adding a page means adding it to `scripts/build-sitemap.js` too, or it ships
orphaned.

## The CSP has no `unsafe-inline`

A stale hash does not degrade, it blocks the whole application script and the
page silently stops working. Two consequences:

- After editing inline script or an inline `on*` handler in `views/index.html`,
  run `npm run sync:csp`.
- `sync-csp-hashes.js` only reads `views/index.html`. A new page that needs
  JavaScript should ship it as a file under `public/` — `script-src 'self'`
  already covers that, and there is nothing to keep in sync. See
  `public/parse-preview.js`.
- A third-party tag needs its origin named in `script-src` (and usually
  `connect-src`). There is no wildcard, so an unnamed tag is blocked outright
  and reports nothing.

## Tests

```
npm test            # node + browser
npm run test:node   # fast
npm run test:browser # Playwright, needs chromium
npm run runtime:check # serverless budget invariants
```

`node --test` runs suites in parallel. A test that inspects shared state — the
system temp directory, say — needs to scope that state to itself or it will be
flaky. `test/parse-preview.test.js` points `TMPDIR` at its own directory for
exactly this reason.

`test/payment.test.js` is the only suite that runs with `DEV_MODE` off. Anything
that only executes on the production path — origin checks, Redis claims, the
retry ladder — has to be asserted there, because `checkOrigin()` and the Stripe,
Redis and Anthropic calls are all short-circuited in dev.

## Serverless budget

The parse and model phases share one deadline (`config/runtime.js`). They do not
each get their own timeout: a Vercel kill at `maxDuration` happens outside the
try/catch, so the analysis claim is never released and a paying customer is
locked out until the claim TTL expires. `npm run runtime:check` asserts the
budget fits, and CI runs it.

## Money paths

- One analysis per payment, enforced by an atomic Redis `SET NX` claim.
- A failure that is not the customer's fault releases the claim. A failure that
  is theirs to fix (unreadable file, password-protected PDF) also releases it.
- Never let an unreadable rate-limit counter or claim read as "allowed" — fail
  closed on the money path, open on the rate limiter, and the comments at each
  site say which and why.
