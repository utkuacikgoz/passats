<wizard-report>
# PostHog post-wizard report

The wizard has completed a deep integration of PostHog into PassATS (`server.js`). The project already had `posthog-node` installed and a basic PostHog client initialized. The integration was extended with five new business-critical event captures, exception autocapture, and a pre-built analytics dashboard.

**Changes made to `server.js`:**
- Added `enableExceptionAutocapture: true` to the PostHog constructor for automatic error tracking with stack traces.
- Added `checkout_initiated` capture when a Stripe checkout session is successfully created.
- Added `payment_completed` capture inside the Stripe webhook handler when `checkout.session.completed` fires, including `amount_total` and `currency`.
- Added `token_replay_blocked` capture when a JWT replay attack is detected.
- Added `cv_analysis_completed` capture on successful analysis, including `overall_score`, `verdict`, `detected_role`, `has_job_description`, and `file_type`.
- Added `cv_analysis_failed` capture (with `retryable` flag) and `posthog.captureException()` in the analysis error handler for rich stack trace tracking.

**Environment variables set in `.env`:**
- `POSTHOG_API_KEY` — your PostHog project token
- `POSTHOG_HOST` — `https://us.i.posthog.com`

| Event | Description | File |
|---|---|---|
| `checkout_initiated` | User successfully started a Stripe checkout session | `server.js` |
| `payment_completed` | Stripe webhook confirmed a completed payment (includes amount & currency) | `server.js` |
| `cv_analysis_completed` | CV was successfully analyzed and scored (includes score, verdict, role) | `server.js` |
| `cv_analysis_failed` | CV analysis failed after token was claimed (includes retry count & retryable flag) | `server.js` |
| `token_replay_blocked` | A JWT was rejected because it had already been used | `server.js` |
| `server_error` (pre-existing) | General server error captured via `logError` helper | `server.js` |

## Next steps

We've built a dashboard and five insights to track user behavior and business health:

- [Analytics basics dashboard](/dashboard/1567016)
- [Checkout → Payment → Analysis Funnel](/insights/wOaTGH9m) — conversion funnel across all three critical steps
- [CV Analyses Completed (Daily)](/insights/ZTcep6Rr) — daily usage volume trend
- [Payments Completed (Daily)](/insights/g7Gyr6qZ) — daily revenue signal
- [CV Analysis Results by Verdict](/insights/wm0RvGmJ) — breakdown of scores by Excellent / Good / Needs Work / Poor
- [Analysis Failures & Errors](/insights/fYtgIz1B) — stability monitor for failed analyses and server errors

### Agent skill

We've left an agent skill folder in your project at `.claude/skills/integration-javascript_node/`. You can use this context for further agent development when using Claude Code. This will help ensure the model provides the most up-to-date approaches for integrating PostHog.

</wizard-report>
