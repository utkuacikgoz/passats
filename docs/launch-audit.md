# PassATS launch audit and go-to-market plan

Audit date: 2026-08-19

## Executive decision

**Recommendation: do not open paid public acquisition yet. Ship a tightly capped,
founder-led beta after the P0 launch gate below is complete.**

The product is stronger than a prototype. It has a coherent low-friction offer,
signed single-use access, global production rate limits, strict upload checks,
temporary-file cleanup, structured model output, useful failure states, and a
57-test suite. Those are meaningful launch assets.

It is not yet an A-player product because its central promise has not been
measured. There is no representative resume/job-description benchmark, no human
review rubric, no regression threshold for score or recommendation quality, and
no production evidence for paid conversion, successful delivery, refunds, or
repeat intent. The application can prove that it returns a valid report; it
cannot yet prove that the report is consistently correct or worth paying for.

### Launch verdict by stage

| Stage | Verdict | Conditions |
| --- | --- | --- |
| Internal production smoke test | **Go** | Use a real Stripe payment, real PDF and DOCX files, the pinned production model, and production Redis. |
| Founder-led beta (25 to 50 users) | **Conditional go** | Complete every P0 item, manually inspect every consenting report, and cap traffic to known channels. |
| Paid public launch | **No-go today** | Require benchmark evidence, funnel instrumentation, support/refund readiness, alerting, budget controls, and a rollback drill. |
| Scaled paid acquisition | **No-go today** | Require proven unit economics and report quality by role before buying volume. |

## Scorecard

This scorecard rates launch readiness, not code aesthetics.

| Area | Score | Evidence and gap |
| --- | ---: | --- |
| Core user flow | 7/10 | One price, no account, PDF/DOCX upload, optional job description, and a structured report make the path easy to understand. The result cannot be recovered after navigation and there is no download, copy, or safe rerun flow. |
| Report quality | 5/10 | The evaluator has unusually specific anti-hallucination and evidence rules. Quality is prompt-tested, not outcome-tested. No golden set or blinded human comparison exists. |
| Security and abuse resistance | 7/10 | Origin checks, signed JWTs, magic-byte checks, file limits, Redis claims, secret gating, CSP, and escaped model text are good foundations. There is no documented threat-model review or external scan. |
| Reliability and operations | 5/10 | Health checks, request IDs, retry handling, cleanup, a smoke script, and CI exist. There is no explicit function-duration configuration, SLO, alert policy, load result, provider budget alarm, or practiced rollback. |
| Billing and support | 5/10 | Stripe Checkout and signed webhooks are implemented. Refund handling is manual, support mailbox readiness is unverified, and the paid recovery journey has not been exercised as an operational process. |
| Privacy and legal | 6/10 | The product discloses processors and deletes its own temporary upload. Processor retention/configuration, consent by geography, records of processing, and deletion verification are not evidenced. Legal review is still required. |
| Analytics and learning | 4/10 | Server events cover checkout initiation, payment, completion, and failures. There is no durable funnel specification, client conversion events, campaign attribution plan, report-quality feedback, or business dashboard. |
| Growth readiness | 4/10 | The offer is differentiated by simplicity and price. Positioning overclaims ATS certainty in structured content, proof is a mock report, and no customer evidence or channel has been validated. |

**Overall launch-readiness rating: 5.4/10.** This is beta-quality, not yet a
self-serve paid acquisition machine.

## What is already strong

1. **The offer has a sharp wedge.** One report for $2.99, no account, and no
   subscription is easy to explain and contrasts with subscription-heavy tools.
2. **Payment access is thoughtfully constrained.** The implementation binds a
   signed token to a Stripe session and uses an atomic Redis claim to prevent
   concurrent reuse.
3. **Uploads receive multiple layers of validation.** The server restricts size,
   MIME type, and magic bytes, parses only supported formats, and deletes its
   temporary file in a `finally` path.
4. **The evaluator prompt is evidence-led.** It tells the model not to invent
   outcomes, not to infer visual layout from extracted text, and to ground fixes
   in named resume sections.
5. **The browser output path escapes model text.** Dynamic report text passes
   through an HTML escaping helper before use in templated markup.
6. **Failure handling is designed for recovery.** Obvious user file mistakes do
   not permanently consume a production claim, while repeated backend failures
   are bounded.
7. **The repository has a real test foundation.** Unit and endpoint tests cover
   extraction, authentication, replay prevention, CSP hashes, schema handling,
   timeouts, and test-token gating.

## Material findings

### P0: must close before the founder-led beta

Implementation status after this audit:

- **P0.1 partially implemented:** the repository now contains a versioned,
  balanced 60-case synthetic fixture, automated fixture/metric tests, and an
  opt-in live-model runner. The live quality gate still requires a real
  `ANTHROPIC_API_KEY`, an exact `LLM_MODEL`, and independent human review before
  it can be marked complete.
- **P0.2 implemented in code:** Node 24.x is aligned across the package, CI, and
  documentation; Vercel has an explicit 120-second/1024 MB function budget; and
  production now requires `LLM_MODEL` rather than silently selecting a fallback.
  A production deployment smoke test remains an operator action.
- **P0.4 implemented in code:** the canonical paid funnel now uses privacy-safe
  anonymous session IDs across landing, Stripe Checkout metadata, payment,
  upload, analysis, and report feedback. Client ingestion is same-origin,
  rate-limited, and strictly allowlisted so resume text, job-description text,
  filenames, tokens, and raw model output are discarded. Production dashboard
  and alert configuration remains an operator action in PostHog.

#### 1. Prove the report, not merely the response shape

Build a versioned golden set of at least 60 consented or synthetic pairs:

- 10 software engineering;
- 10 product/project management;
- 10 data;
- 10 marketing/sales;
- 10 finance/operations; and
- 10 career-change, entry-level, sparse, unusual, and adversarial resumes.

For each pair, have two experienced resume reviewers independently label hard
requirements, present/missing terms, unsupported claims, the three highest-value
fixes, and severity. Blind the reviewers to PassATS output. Track:

- hard-requirement precision and recall;
- missing-keyword precision;
- unsupported-claim rate;
- actionable top-three precision;
- score repeatability over three identical runs;
- inter-reviewer agreement; and
- latency, token usage, and cost per successful report.

Suggested launch thresholds: zero invented facts in the release set, at least
90% missing-keyword precision, at least 85% hard-requirement recall, at least 80%
reviewer acceptance for the top three fixes, less than 5 points median score
spread across repeated runs, p95 end-to-end latency under 45 seconds, and at least
98% successful analyses for valid text PDFs/DOCX files. Thresholds are operating
targets to validate, not marketing claims.

Add the benchmark to CI as a sampled deterministic contract test where possible,
and run the full paid-model evaluation manually before model or prompt changes.

#### 2. Resolve runtime and timeout ambiguity

The repository advertises Node 20+ in its README and tests Node 20 in CI, while
`package.json` requires Node 24.x. Pick one production runtime, verify every native
dependency there, and make all three declarations agree.

The model timeout is 55 seconds and parsing can take 15 seconds, yet Vercel has no
explicit maximum-duration setting in this repository. Confirm the production plan
and set an explicit duration with headroom for parsing, model work, cleanup, and
the HTTP response. A 55-second model timeout is not a 60-second end-to-end budget.

Pin and validate the exact Anthropic model ID in a production smoke test. Do not
assume a friendly model name accepted today will remain a stable API identifier.
Record model ID and prompt version with every operational analysis event.

#### 3. Establish paid-delivery and refund operations

- Make `support@passats.com` and `privacy@passats.com` deliver to monitored inboxes.
- Create macros for failed analysis, duplicate charge, unusable report, privacy
  request, and refund.
- Define who answers, the response SLO, refund authority, and weekend coverage.
- Test one successful refund and its Stripe reconciliation before launch.
- Add a plain-language recovery route to the failure UI, including the request ID.
- Decide what happens when a customer closes the tab or loses the report. The
  current no-account/no-storage promise makes report recovery impossible; state
  that before payment or offer a privacy-preserving download immediately after
  generation.
- Verify the Checkout statement descriptor, receipt settings, tax configuration,
  business identity, refund policy, and customer-facing support details.

#### 4. Install an observable launch funnel

Define one canonical event contract with no resume or job-description text:

1. `landing_viewed`
2. `checkout_clicked`
3. `checkout_created`
4. `payment_completed`
5. `upload_viewed`
6. `file_validation_failed`
7. `analysis_started`
8. `analysis_completed`
9. `analysis_failed`
10. `report_feedback_submitted`

Attach anonymous session/campaign identifiers, request ID, coarse role category,
file type, whether a job description was supplied, model ID, prompt version,
latency bucket, and failure category. Never attach document text, job-description
text, names, contact details, filenames, JWTs, Stripe checkout URLs, or raw model
responses.

Create dashboards and alerts for checkout creation errors, payment-to-report
completion, failure rate, p50/p95 latency, provider spend, Redis errors, refunds,
and support volume. Decide alert owners before traffic arrives.

#### 5. Remove claims that the product cannot substantiate

Avoid saying a single score “decides” whether a resume reaches a human, assigning
universal pass/fail cutoffs, or implying compatibility with every ATS vendor. The
implementation evaluates extracted text with an LLM; it does not submit a file to
Workday, Greenhouse, Lever, Taleo, or another named parser. Position the score as a
consistent diagnostic benchmark and the job-description comparison as the main
value. Align HTML FAQ structured data, visible FAQ copy, metadata, `llms.txt`, and
ads so crawlers and customers receive the same qualified promise.

### P1: close before broad public launch

#### Reliability and security

- Load-test checkout, verification, upload, Redis limits, and analysis concurrency
  at 2x the planned launch peak. Confirm Anthropic, Redis, Stripe, and Vercel quotas.
- Test malformed ZIP/DOCX bombs, large decompressed documents, PDFs with complex
  objects, duplicate multipart fields, slow uploads, provider timeouts, webhook
  retries, Redis failure, and concurrent token reuse.
- Add a dependency update policy with lockfile review. Keep dependency audit and
  secret scanning required on the protected branch.
- Set provider budget limits and alerts. Add an emergency kill switch that disables
  new checkout while leaving paid analyses and static support information working.
- Create a rollback runbook and perform one rollback drill.
- Verify logs and PostHog cannot capture uploaded text through exception objects.
- Document key rotation for JWT, Stripe webhook, Upstash, Anthropic, PostHog, health,
  and owner-test credentials. Disable the owner endpoint when not actively testing.

#### Product experience

- Let users copy or download the report locally without creating an account.
- Explain before payment that image-only PDFs are unsupported, reports are not
  stored/recoverable, one purchase produces one analysis, and the job description
  materially improves relevance.
- Give the customer a safe file-validation step before or immediately after
  payment so unsupported files do not create support friction.
- Add report-level feedback: useful/not useful plus an optional reason that cannot
  contain resume text by default.
- Test mobile, keyboard-only, screen reader, reduced motion, 200% zoom, and the two
  latest versions of Chrome, Safari, Firefox, and Edge.
- Test the full purchase and report path on mobile connections, not only the landing
  page.

#### Legal and privacy

- Obtain jurisdiction-appropriate legal review; this audit is not legal advice.
- Confirm processor terms and retention settings for Anthropic, Vercel, Stripe,
  Upstash, and PostHog match the public policy.
- Document data flow, lawful basis/consent, retention by data class, access control,
  deletion requests, incident response, and subprocessor changes.
- Decide launch geographies deliberately. Configure tax, consumer cancellation,
  privacy notices, and analytics consent accordingly.
- Add version/effective dates and a business identity to terms and privacy pages.

### P2: improve after a measured beta

- Add role-calibrated report templates only where benchmark data shows a gap.
- Provide a compare-after-edit workflow without weakening one-purchase economics;
  test a two-scan package rather than silently making the token reusable.
- Add local report export, a checklist view, and copyable rewritten bullets.
- Publish a transparent methodology page with what the tool can and cannot see.
- Build programmatic landing pages only from genuine role-specific evaluation data,
  not thin SEO variants.

## Deployment audit checklist

Every checkbox needs an owner, evidence link, completion date, and rollback step.

### Release integrity

- [ ] Production deploy comes from a reviewed, protected, tagged commit.
- [ ] `npm ci`, `npm test`, dependency audit, secret scan, and `git diff --check` pass.
- [ ] Node version is identical in `package.json`, CI, documentation, and Vercel.
- [ ] Production model ID and prompt version are pinned and recorded.
- [ ] Golden-set quality thresholds pass on the release candidate.
- [ ] Vercel function duration and memory are explicit and tested.
- [ ] Native PDF/canvas dependencies work in a production-equivalent cold start.
- [ ] Rollback target and operator are documented; rollback drill passes.

### Configuration and secrets

- [ ] `DEV_MODE` is absent in production.
- [ ] `BASE_URL` is the exact canonical HTTPS origin; allowed preview origins are intentional.
- [ ] Stripe uses live keys, the intended live price, and the correct webhook secret.
- [ ] JWT secret is random and unique; previous-secret rotation is tested.
- [ ] Upstash is a dedicated production database with capacity and spend alerts.
- [ ] Anthropic billing, rate limits, data settings, and spend alerts are verified.
- [ ] Health and owner-test secrets are unique; owner-test access is disabled or IP-restricted.
- [ ] PostHog host/project and privacy settings are production-correct.
- [ ] No secret, token, personal data, resume text, or job description appears in logs.

### Domain, delivery, and web surface

- [ ] Custom production domain, DNS, TLS, redirect, and canonical URLs are correct.
- [ ] Sitemap, robots, Open Graph image, structured data, and policy links use that domain.
- [ ] `support@` and `privacy@` receive and send successfully with SPF, DKIM, and DMARC.
- [ ] Security headers are verified on HTML and appropriate API routes in production.
- [ ] A 404 returns a true 404 or an intentional SPA response; API routes never fall through to HTML.
- [ ] HTML caching permits fast corrections; immutable assets are content-versioned.

### Payments

- [ ] Price, currency, tax, receipts, statement descriptor, business name, and support details are correct.
- [ ] Checkout success, cancellation, abandoned checkout, webhook retry, and duplicate webhook are tested.
- [ ] Only the intended product/price/payment state grants an analysis.
- [ ] Payment verification and claim behavior pass a concurrent-replay test.
- [ ] One real live payment reaches one real report on desktop and mobile.
- [ ] Refund and dispute runbooks are tested and reconciled.

### Upload and analysis

- [ ] Valid text PDF and DOCX files work across small, large, and unusual examples.
- [ ] Image-only, corrupt, encrypted, oversized, false-MIME, and decompression-bomb files fail safely.
- [ ] Failed validation does not consume the paid analysis.
- [ ] Temporary files disappear after success, client disconnect, parse error, timeout, and model error.
- [ ] Job-description length and multipart limits behave as advertised.
- [ ] Prompt injection fixtures do not alter evaluator instructions or leak system text.
- [ ] Model refusal, invalid output, timeout, throttling, and provider outage produce useful recovery states.
- [ ] The report never invents candidate facts in the release benchmark.

### Observability and incident readiness

- [ ] Health monitor checks all critical dependencies with the secret header.
- [ ] Dashboards show landing-to-checkout, checkout-to-payment, payment-to-report, and refund rates.
- [ ] Alerts cover elevated 5xx, analysis failures, Redis failures, webhook failures, latency, and spend.
- [ ] Request IDs join customer errors to sanitized server events.
- [ ] On-call owner, escalation path, incident template, status message, and kill switch are ready.
- [ ] Backups/config exports and restoration steps are documented where applicable.

### Customer and compliance readiness

- [ ] Pre-purchase copy explains supported files, single use, no storage/recovery, and refund path.
- [ ] Terms, privacy, processor disclosures, business identity, and effective dates are reviewed.
- [ ] Analytics consent behavior matches each launch geography.
- [ ] Accessibility and browser matrix pass.
- [ ] Ten outsiders complete an observed usability test without founder intervention.
- [ ] Support macros, SLO, staffing, and refund authority are active.

## Go-to-market strategy

### 1. Choose a narrow beachhead

Start with **English-language individual contributors applying to a specific job
with an existing PDF/DOCX resume**. Within that, recruit the first cohort from
software, product, data, marketing, and finance so the benchmark and acquisition
learning share the same role taxonomy.

Do not market “beat every ATS.” Own this job instead:

> Before you apply, compare this resume with this job description and get the
> three evidence-backed fixes that matter most. One private report. No account or
> subscription.

The job-description-specific use case is more defensible than a universal ATS
score. The score is the orientation device; the cited gaps and fixes are the
product.

### 2. Package and price for learning

Keep $2.99 for the beta because it removes subscription anxiety and makes paid
intent cheap to test. Do not infer strong willingness to pay from conversion at
that price.

Run sequential, not simultaneous, pricing tests after quality is proven:

1. one report at $2.99;
2. one report at $4.99 with a clear usefulness guarantee; and
3. a $7.99 “apply pack” with an original scan and one edited-resume rescan for the
   same job description.

Use net revenue after Stripe fees, refunds, model cost, support time, and taxes.
Choose on contribution margin and qualified report completion, not checkout rate
alone. Never introduce a subscription until interviews reveal a recurring job;
the no-subscription promise is currently a differentiator.

### 3. Build proof before promotion

The first 25 to 50 customers are a research cohort, not a launch vanity metric.

- Recruit through founder network, role-specific communities where promotion is
  permitted, university career services, bootcamp alumni, outplacement coaches,
  and independent career coaches.
- Give invited users a normal paid checkout and refund the fee after a 15-minute
  interview. This tests the real purchase journey without pretending free users
  show paid intent.
- Ask users to score accuracy, specificity, actionability, and value before showing
  any founder interpretation.
- Ask what they changed, whether they would use the edited-resume rescan, what they
  expected before paying, and what nearly stopped them.
- With explicit permission, turn only verified before/after examples into proof.
  Do not claim interview or hiring outcomes without controlled evidence.

Exit the cohort when at least 80% rate the top three fixes useful, fewer than 5%
request a quality refund, valid-file completion exceeds 95%, and at least 30% say
they would be very disappointed if the product disappeared. These are proposed
decision rules, not established performance.

### 4. Message hierarchy

Use one consistent message across landing pages, posts, partners, and checkout:

1. **Outcome:** know what to fix before this application.
2. **Mechanism:** compare the resume with the actual job description.
3. **Proof:** show a redacted input line beside the exact, evidence-grounded fix.
4. **Risk reversal:** one low payment, no subscription, private processing, clear
   technical-failure refund path.
5. **Boundary:** a diagnostic benchmark, not a hiring guarantee or vendor parser.

Test these angles one at a time:

- “Three fixes before you apply” for urgency;
- “Paste the job description” for relevance;
- “No $30 subscription” for category contrast; and
- “Your file is discarded after analysis” for privacy.

Measure completed paid reports and useful-report feedback by angle. CTR alone is
not a winning message.

### 5. Channel sequence

#### Phase A: weeks 1 and 2, founder-led learning

- Publish five redacted teardown posts, one for each initial role family. Show the
  input evidence, the bad generic suggestion the product avoids, and the specific
  fix it gives.
- Personally invite 5 to 10 relevant applicants per day.
- Partner with 5 career coaches. Give each a campaign link and free test reports,
  not a permanent commission yet.
- Interview every consenting customer within 48 hours.

Primary goal: 30 completed reports and 20 interviews. Success is quality evidence,
not reach.

#### Phase B: weeks 3 and 4, repeatable organic acquisition

- Turn the best teardown format into a weekly series for LinkedIn, YouTube Shorts,
  TikTok, and role communities, adapting the creative rather than cross-posting
  identical copy.
- Publish methodology, limitations, and five role guides backed by benchmark data.
- Offer coaches a co-branded checklist and a tracked link. Pay only for completed,
  non-refunded reports after the channel shows incremental demand.
- Create job-description-first landing variants by role only where report quality
  has passed the role benchmark.

Primary goal: one channel produces at least 50 paid reports with stable quality
and positive contribution before founder labor.

#### Phase C: weeks 5 through 8, controlled paid tests

- Retarget visitors who reached checkout only if consent and geography permit.
- Test high-intent search terms around resume/job-description matching with a hard
  daily cap. Exclude broad “resume template” traffic.
- Send each ad to the closest role/use-case page and preserve campaign attribution
  through Stripe and report completion.
- Stop a campaign after its predeclared spend cap if it cannot show positive
  contribution or useful-report quality. Do not optimize to cheap clicks.

Primary goal: one paid segment recovers fully loaded acquisition cost on the first
purchase, or demonstrates credible pack/rescan revenue that does so.

### 6. Funnel and operating metrics

Use this weekly scorecard:

| Layer | Metric | Initial decision threshold |
| --- | --- | ---: |
| Acquisition | Qualified landing sessions by role/source | Report, no universal target |
| Intent | Checkout clicks / qualified sessions | Diagnose by source and device |
| Purchase | Paid sessions / checkout-created sessions | Investigate material source/device drops |
| Delivery | Completed reports / paid sessions | >= 95% beta; target >= 98% before scale |
| Quality | Users accepting >= 2 of top 3 fixes | >= 80% |
| Trust | Quality refunds / completed reports | < 5% beta, trending down |
| Engagement | Reports with job description | >= 70% because this is the core wedge |
| Economics | Contribution after variable costs / completed report | Positive before paid scale |
| Support | Tickets / completed reports and median first response | Trend and staff explicitly |
| Advocacy | Willing to recommend and permissioned testimonials | Report by cohort, not blended |

The thresholds above are launch hypotheses. Replace them with cohort evidence and
never present internal thresholds as validated industry benchmarks.

### 7. Experiment backlog

Prioritize by risk removed:

1. Blinded report-quality benchmark.
2. Job description required versus optional, measuring completion and usefulness.
3. Real sample-report proof versus decorative mock report.
4. $2.99 versus $4.99 sequential price cohorts.
5. One report versus original-plus-rescan pack.
6. “Three fixes” versus “ATS score” hero message.
7. Privacy proof beside CTA versus below the fold.
8. Coach referral cohort versus founder social cohort.
9. Local PDF download versus browser-only results.
10. Usefulness guarantee versus technical-failure-only refund language.

For every experiment, write the hypothesis, primary metric, guardrail metrics,
minimum sample, stop condition, and decision before launching it. Segment report
quality alongside conversion so growth never selects for customers the product
serves poorly.

## Final recommendation

PassATS has enough engineering discipline for a controlled production beta. It
does not yet have enough evidence for a confident public launch. Spend the next
cycle proving the analysis, aligning runtime limits, instrumenting paid delivery,
and preparing support. Then launch to a narrow job-description-first segment and
earn distribution with transparent, redacted teardowns. Scale only the roles and
channels where report quality and contribution margin are both demonstrated.
