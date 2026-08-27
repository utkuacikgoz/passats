# PassATS

PassATS is a paid ATS resume scoring service built on Express, Stripe, Upstash Redis, and Claude structured output.

## Layout

```
server.js          the whole Express app
api/index.js       Vercel entry point — exists so vercel.json can set maxDuration
lib/               logic with enough surface to test on its own (hidden-text scan)
views/             HTML documents, always served by the function so the CSP applies
public/            static assets only (icons, OG image, tokens.css, robots, sitemap)
scripts/           generators (CSP hashes, FAQ structured data, sitemap, OG image)
test/              unit, e2e (dev mode), payment (production path), browser (Playwright)
```

`views/` is deliberately outside `public/`. Anything in `public/` is served by
Vercel's CDN before the function runs, which would deliver the HTML without the
security headers and hashed CSP that `server.js` sets.

## Runtime

- Node — the version in `.nvmrc` is the single source. CI reads it via
  `node-version-file`, `nvm use` reads it locally, and Vercel resolves
  `engines` to the newest release of that major. The floor is 22.22.0 because
  `posthog-node` declares `^20.20.0 || >=22.22.0`; anything lower installs with
  an `EBADENGINE` warning.
- Vercel or another Node-compatible serverless/container runtime
- Stripe checkout + webhook configured
- Upstash Redis for one-analysis-per-payment enforcement and global rate limiting
- Anthropic API key for Claude
- Optional PostHog project key for server-side error tracing

## Environment

Required in production:

- `ANTHROPIC_API_KEY`
- `LLM_MODEL` (default when unset: `claude-sonnet-5`; use `claude-haiku-4-5` for lower cost/latency)
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `STRIPE_PRICE_ID`
- `JWT_SECRET`
- `UPSTASH_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN`
- `SUPPORT_EMAIL` — the refund route. Defaults to `support@passats.com`; must be a mailbox you read.

Recommended optional variables:

- `HEALTH_SECRET` for `/api/health`
- `POSTHOG_API_KEY` for server-side error tracing
- `POSTHOG_HOST` for US/EU/self-hosted PostHog
- `TEST_SECRET` for `/api/test-token`
- `COUPON_CODES` for free tester analyses
- `COUPON_EXPIRES_AT` to expire every coupon at once
- `TEST_ALLOWED_IPS` for `/api/test-token`
- `BASE_URL`
- `PORT`

## Local Development

1. Run `nvm use` to match the Node version in `.nvmrc`.
2. Copy `.env.example` to `.env` and fill the values you need.
3. For local UI/testing without live billing or live LLM calls, set `DEV_MODE=true`.
4. Install dependencies with `npm install`.
5. Start the app with `npm run dev`.
6. Install the browser used by the journey tests once: `npx playwright install chromium`.
7. Run the test suite with `npm test`.

## Generated Files

Four files are generated, never hand-edited. CI fails if the first two are stale.

| Command | Regenerates | From |
| --- | --- | --- |
| `npm run sync:csp` | CSP hashes in `server.js` | the inline scripts and handlers in `views/index.html` |
| `npm run sync:faq` | FAQPage JSON-LD in `views/index.html` | the visible FAQ on the same page |
| `npm run sync:sitemap` | `public/sitemap.xml` | git history for each page |
| `npm run build:og` | `public/og-image.png` | `public/og-image.svg` |

`npm run sync:seo` runs the first three. Run `sync:csp` after **any** edit to
`views/index.html`: the policy has no `'unsafe-inline'` fallback, so a stale hash
does not degrade the page, it blocks the entire application script.

## The Free Parse Preview

`/ats-parse-preview` shows the plain text an ATS reads out of an uploaded file.
No score, no keywords, no fixes, and no model call, so it costs a parse and
nothing else. It exists for links: nobody points a careers page or a roundup at a
checkout, and seeing your own CV come back as flat text argues for the paid
analysis better than any copy on the landing page.

Three things about it are deliberate:

- **It runs the same extraction the paid path runs**, hidden-text pass included,
  so what it shows is what would actually be scored. The hidden text is reported
  but never echoed back — returning it would make this a way to check that your
  keyword stuffing survived extraction.
- **A file it cannot parse is a 422, not a 500.** Corrupt PDFs are ordinary input
  here. Logging them as errors would page us for every truncated CV export, and
  "an ATS could not read this either" is the most useful thing the page can say.
- **Its script is `public/parse-preview.js`, not an inline block.** The CSP has no
  `'unsafe-inline'`, and `sync-csp-hashes.js` only reads `views/index.html`, so an
  inline script here would break silently the first time someone edited the page
  without re-running the sync. `script-src 'self'` covers a file, with nothing to
  keep in sync.

It is unauthenticated and it burns CPU, so it is rate limited well below anything
a real visitor would reach (`PARSE_PREVIEW_MAX_PER_WINDOW`).

## Hidden Text In Uploads

A résumé can carry text a human reader never sees: PDF render mode 3, white on a
white page, a font scaled below legibility, or `w:vanish` in a DOCX. All of it
reaches the text layer, so without a check it lands in the prompt and inflates
the keyword score. `lib/hidden-text.js` reads the file a second time — through
pdfjs's operator list for PDFs, the run properties for DOCX — cuts what it finds
out of the text before the prompt is built, and the server reports it as a
critical finding. The model never sees the hidden text and never writes that
finding, so a document that is already gaming the score cannot argue it away.

Two properties matter more than coverage:

- **It does not accuse.** White text on a dark sidebar and a 1pt font scaled up
  by the text matrix are both normal typesetting, and a scanned page's OCR layer
  is invisible by design. Each is gated, and `test/hidden-text.test.js` builds a
  real file for each one and asserts it comes back clean.
- **It cannot cost anyone their analysis.** The scan is capped by
  `HIDDEN_TEXT_TIMEOUT_MS` inside the document-parse ceiling, and every failure
  path returns the original text.

The one vector still open is text painted behind an opaque image, which needs
geometry the operator list alone does not settle.

## Prompt Evaluation

The analysis prompt is the product, and every question about it — does the same
CV score the same twice, did an edit help or hurt — needs measurement rather than
opinion.

```
ANTHROPIC_API_KEY=... npm run eval               # all fixtures, 3 runs each
ANTHROPIC_API_KEY=... npm run eval -- --runs 5
ANTHROPIC_API_KEY=... npm run eval -- --only nurse
ANTHROPIC_API_KEY=... npm run eval -- --json before.json
```

Fixtures live in `eval/cvs/*.txt` as plain CV text, which isolates prompt quality
from document parsing. Three ship by default: a strong software engineer CV, a
weak marketing one, and a nurse — the last deliberately outside the five job
families the prompt lists keywords for.

The harness reports two things and exits non-zero on either:

- **Score spread** across identical runs. Default budget is 3 points; raise it
  with `--max-spread`. A wide spread is the known open finding: the prompt's
  PENALTIES and BONUSES never state whether they apply to a component score or
  to the weighted total, and the two readings differ by a factor of three.
- **Rule compliance**, checked mechanically: banned hedging phrases, em and en
  dashes, layout claims rule 8 forbids, list lengths, missing score impacts, and
  issue details too short to be specific.

It does not judge whether the advice is good. Read a sample by hand for that.
Each run costs roughly $0.03. To compare two prompt versions, write `--json` on
each side and diff the summaries.

The harness's judgement is unit-tested in `test/eval.test.js`, which runs without
an API key — a checker that silently passes everything would certify a
regression as clean.

## Analytics

Server-side events cover money and outcomes: `checkout_initiated`,
`payment_completed`, `cv_analysis_completed`, `cv_analysis_failed`,
`token_replay_blocked`, `server_error`.

Browser-side funnel events are relayed through `POST /api/event` rather than a
third-party script, which keeps the CSP at `connect-src 'self'`, loads no
tracking script or cookie, and makes it structurally impossible for resume
content to reach an analytics tool: the endpoint accepts an event name from a
fixed allowlist plus a tab-scoped random id, and nothing else.

`landing_viewed` · `checkout_clicked` · `upload_view_reached` ·
`analysis_started` · `report_viewed` · `report_saved`

The id is passed to `/api/checkout` as well, so the browser funnel and the
payment events can be joined in PostHog.

## Where To Get Environment Variables

- `ANTHROPIC_API_KEY`: Anthropic Console, API keys page.
- `LLM_MODEL`: choose manually; default is `claude-sonnet-5`. `claude-haiku-4-5` trades a little copy sharpness for lower cost/latency.
- `STRIPE_SECRET_KEY`: Stripe Dashboard, Developers, API keys.
- `STRIPE_WEBHOOK_SECRET`: Stripe Dashboard, Developers, Webhooks, then reveal the endpoint signing secret.
- `STRIPE_PRICE_ID`: Stripe Dashboard, Products, open the price and copy the `price_...` identifier.
- `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`: Upstash Redis console, database details.
- `JWT_SECRET`, `JWT_SECRET_PREV`, `HEALTH_SECRET`, `TEST_SECRET`: generate and manage these yourself as deployment secrets.
- `TEST_ALLOWED_IPS`: your public IP address or a comma-separated allowlist for owner smoke tests.
- `POSTHOG_API_KEY`: PostHog project settings, Project API Key.
- `POSTHOG_HOST`: use `https://us.i.posthog.com`, `https://eu.i.posthog.com`, or your self-hosted domain.

For local development, put them in `.env` next to `.env.example`.
For production, set them in your deployment platform, which is typically Vercel Project Settings, Environment Variables.

## Production Audit

Before go-live, verify the following:

- `DEV_MODE` is not set in production.
- Vercel project uses Node 22.x, matching `engines` and CI.
- **Routing survives the move off `builds`.** Run
  `BASE=https://your-preview.vercel.app npm run smoke:routes` against the first
  preview deploy, before promoting it. Fifteen checks cover the catch-all rewrite
  into `api/index.js`, static assets still winning over it, the `.html` redirects,
  and — via the CSP and `X-Frame-Options` headers on `/` — that HTML is genuinely
  served by the function rather than the CDN. This is the one change the test
  suite cannot prove locally.
- **The deployed function's real timeout is at least 60 s.** `vercel.json` asks for
  `maxDuration: 60`; confirm the deployment honoured it. `LLM_TIMEOUT_MS` is 55 s,
  and a platform timeout kills the request *outside* our catch block, so the
  analysis claim is never released and the customer is locked out of the analysis
  they paid for. If the plan caps duration lower, lower `LLM_TIMEOUT_MS` to match.
- **The consent line survived.** Checkout sends `custom_text.submit` carrying the
  withdrawal waiver, and falls back to a plain session if Stripe rejects it rather
  than failing the sale. Grep the logs for `checkout.custom_text_rejected` after
  the first live purchase: if it appears, the waiver is only on the terms page.
- **`SUPPORT_EMAIL` resolves to a mailbox someone reads.** Send a test message to
  it. It is quoted in the terminal failure message and in the terms as the refund
  route; a customer who lost $2.99 with no reachable address opens a Stripe
  dispute instead, which costs about $15.
- **The canonical domain is decided and consistent.** `BASE_URL`, the `canonical`
  tags, `sitemap.xml`, and the support address should all point at the same
  origin. They currently mix `passats.vercel.app` and `passats.com`.
- **The legal placeholders are filled in.** `views/terms.html` and
  `views/privacy.html` contain `[LEGAL ENTITY NAME]`, `[JURISDICTION]`, and
  `[REGISTERED ADDRESS]`. Shipping those literal strings to customers is worse
  than having no clause.
- **IP trust is verified.** Rate limits and the `/api/test-token` allowlist key on
  `x-vercel-forwarded-for`, falling back to `req.ip`. From a machine outside the
  allowlist, send `x-forwarded-for` set to an allowlisted IP against production
  `/api/test-token` and confirm it still returns `404`.
- Stripe webhook in production points to `/api/webhook` and uses the production signing secret.
- `JWT_SECRET` is long, random, and stored only in the deployment platform secret store.
- Upstash Redis is a production database, not a shared or dev instance.
- Redis-backed rate limiting is global, so verify the shared Upstash instance has enough headroom for launch traffic.
- `HEALTH_SECRET` is set and your uptime monitor sends the `x-health-secret` header.
- `POSTHOG_API_KEY` is set if you want server-side errors traceable in PostHog.
- `TEST_SECRET` is either unset or rotated to an owner-only secret if you want smoke-test access.
- `TEST_ALLOWED_IPS` is set to your public IP if `/api/test-token` is enabled. Without it, the endpoint stays disabled.
- `COUPON_CODES` is unset unless you are actively running testers, and every code in it is long and random. Codes grant the paid product for free.
- Anthropic billing and rate limits are confirmed for your traffic profile.
- `LLM_MODEL` is pinned to `claude-sonnet-5` (or `claude-haiku-4-5`), an explicitly chosen stable model, not a dated snapshot alias.
- A real payment-to-analysis smoke test is completed in production before opening traffic.

## Unit Economics

At list pricing, one analysis costs roughly:

| Request | Input tokens | Output tokens | Cost |
| --- | --- | --- | --- |
| Typical two-page CV, no job description | ~3.5K | ~1.2K | ~$0.029 |
| 40K-character CV plus a 12K-character job description | ~16K | ~3.0K | ~$0.09 |

Against $2.99 less roughly $0.39 in Stripe fees, gross margin stays above 96%
even in the worst case. **The model choice is a quality decision, not a cost
one** — do not downgrade it to save three cents per report; the specificity of
the output is the entire product.

Two things to keep an eye on:

- **Claude Sonnet 5 introductory pricing ($2 / $10 per million tokens) ends
  2026-08-31**, reverting to $3 / $15. Cost of goods rises about 50% overnight.
- **Prompt caching is deliberately off.** The fixed system prompt is about 2,300
  tokens, comfortably over the ~1,024-token minimum, so caching would cut roughly
  90% off that portion on a hit. But the five-minute TTL and the 1.25x write cost
  make it net-negative below sustained traffic. Revisit when analyses run more
  often than once every five minutes.

## Coupon Codes

Coupons give a tester one free analysis each, without touching Stripe. A redeemed
coupon mints the same upload token a payment does, so everything downstream is
identical: one analysis per redemption, the same retry ladder, the same replay
block.

Set them in your deployment environment:

```
COUPON_CODES=FRIENDS-7XK2Q9:5,BETA-M4RT8W:1
```

Each entry is `CODE:maxRedemptions`. Omit the count and it defaults to 1. Codes
are matched case-insensitively with spaces stripped, so a tester retyping one
from a message will not be tripped by capitalisation.

Optionally kill the whole programme at a fixed time, whatever the caps say:

```
COUPON_EXPIRES_AT=2026-10-01T00:00:00Z
```

### Rules this follows

- **Unset means nothing works.** There is no default code.
- **Use long random codes.** These hand out the paid product. `FRIENDS` is
  guessable in seconds; `FRIENDS-7XK2Q9` is not.
- **Redemptions are counted in Redis and never reset.** The counter has no TTL,
  so a spent coupon stays spent.
- **A Redis outage denies redemption.** This is the opposite of the analysis
  retry counter, which fails open to protect someone who already paid.
- **Unknown, expired and spent codes all answer the same 404.** Probing cannot
  discover which codes exist.
- **The live code never leaves the environment.** Redis keys, logs and analytics
  all carry a SHA-256 prefix instead.
- Coupon analyses report `source: "coupon"` in telemetry, so free runs stay out
  of your revenue numbers.

### Retiring a code

Remove it from `COUPON_CODES` and redeploy. To reuse a code name later, also
delete its Redis key, since the redemption count persists deliberately.

## Suggested Pre-Launch Smoke Tests

1. Complete a real Stripe purchase and verify `/success` can fetch a valid token.
2. Upload a valid text PDF and confirm a Claude-backed report is returned.
3. **Refresh the page on the report and confirm the report comes back.** Then
   refresh between paying and uploading and confirm the upload screen returns.
4. Reuse the same token and confirm replay is blocked with `403`.
5. Upload an invalid file and confirm the token is not burned unnecessarily.
6. Upload a 6 MB file and a 25,000-character job description, and confirm both
   return a specific `413` JSON message rather than an HTML error page.
7. Hit `/api/health` with the correct secret header and verify `hasLlm`, `hasStripe`, `hasRedis`, and optionally `hasPostHog` are `true`.
8. Confirm `payment_completed` and `cv_analysis_completed` appear in PostHog —
   these are flushed before the response, but the flush is bounded and best-effort.

## Routing Smoke Check

```
BASE=https://your-deployment.vercel.app npm run smoke:routes
```

Read-only, no payment, safe against production. Exits non-zero on any failure and
names what broke. It also detects two situations where the result would otherwise
be misleading:

- **Deployment Protection.** Vercel preview URLs sit behind SSO by default, and
  answer every request with their own login page. The script detects this and
  stops rather than reporting fifteen failures that describe the gate, not the
  app. Create a Protection Bypass for Automation secret under Project Settings,
  Deployment Protection, then re-run with `VERCEL_BYPASS_TOKEN=<secret>`.
- **Degraded boot.** A 503 on `/api/*` means the deployment is missing required
  environment variables. The server logs name which ones.

## Production Smoke Script

Use the built-in smoke script to exercise checkout, token verification, and analysis:

1. Run `PASSATS_BASE_URL=https://your-domain.com PASSATS_HEALTH_SECRET=... npm run smoke:prod`.
2. The script will create a checkout session and print the Stripe checkout URL.
3. Complete the purchase in the browser and capture the `session_id` from the `/success` redirect.
4. Rerun with `PASSATS_SESSION_ID=cs_... PASSATS_BASE_URL=https://your-domain.com npm run smoke:prod` to verify payment and run a live analyze request.

Owner-only shortcut:

1. Set both `TEST_SECRET` and `TEST_ALLOWED_IPS` in production. Example: `TEST_ALLOWED_IPS=203.0.113.10`.
2. If your current public IP is allowlisted, you can run `PASSATS_BASE_URL=https://your-domain.com PASSATS_TEST_SECRET=... npm run smoke:prod`.
3. That still checks checkout creation, then uses `/api/test-token` to skip the manual payment step and exercise analysis directly.

To run a real, no-payment analysis of a specific CV and print the raw model report (useful for eyeballing output quality after a model change):

```
TEST_SECRET=your-secret npm run owner:analyze -- path/to/resume.pdf "optional job description"
```

To test the production upload and results UI without payment, run:

```
TEST_SECRET=your-secret npm run owner:ui
```

Open the printed URL in a browser. It contains a single-use, 30-minute owner test token in the URL fragment; the page removes it from browser history before showing the upload screen.

Same requirements: `TEST_SECRET` set in the deployment env, and your public IP in `TEST_ALLOWED_IPS`. Override the target with `BASE=https://your-domain.com`. Remove `TEST_SECRET` when finished to disable the endpoint.
