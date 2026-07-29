# PassATS

PassATS is a paid ATS resume scoring service built on Express, Stripe, Upstash Redis, and Claude structured output.

## Runtime

- Node 20+
- Vercel or another Node-compatible serverless/container runtime
- Stripe checkout + webhook configured
- Upstash Redis for single-use token replay protection and global rate limiting
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

Recommended optional variables:

- `HEALTH_SECRET` for `/api/health`
- `POSTHOG_API_KEY` for server-side error tracing
- `POSTHOG_HOST` for US/EU/self-hosted PostHog
- `TEST_SECRET` for `/api/test-token`
- `TEST_ALLOWED_IPS` for `/api/test-token`
- `BASE_URL`
- `PORT`

## Local Development

1. Copy `.env.example` to `.env` and fill the values you need.
2. For local UI/testing without live billing or live LLM calls, set `DEV_MODE=true`.
3. Install dependencies with `npm install`.
4. Start the app with `npm run dev`.
5. Run the test suite with `npm test`.

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
- Vercel project uses Node 20+.
- Stripe webhook in production points to `/api/webhook` and uses the production signing secret.
- `BASE_URL` matches the live canonical domain exactly, including protocol.
- `JWT_SECRET` is long, random, and stored only in the deployment platform secret store.
- Upstash Redis is a production database, not a shared or dev instance.
- Redis-backed rate limiting is now global, so verify the shared Upstash instance has enough headroom for launch traffic.
- `HEALTH_SECRET` is set and your uptime monitor sends the `x-health-secret` header.
- `POSTHOG_API_KEY` is set if you want server-side errors traceable in PostHog.
- `TEST_SECRET` is either unset or rotated to an owner-only secret if you want smoke-test access.
- `TEST_ALLOWED_IPS` is set to your public IP if `/api/test-token` is enabled. Without it, the endpoint stays disabled.
- Anthropic billing and rate limits are confirmed for your traffic profile.
- `LLM_MODEL` is pinned to `claude-sonnet-5` (or `claude-haiku-4-5`), an explicitly chosen stable model, not a dated snapshot alias.
- Error monitoring is attached to PostHog or another log sink so failed analyses can be traced by request ID.
- A real payment-to-analysis smoke test is completed in production before opening traffic.

## Suggested Pre-Launch Smoke Tests

1. Complete a real Stripe purchase and verify `/success` can fetch a valid token.
2. Upload a valid text PDF and confirm a Claude-backed report is returned.
3. Reuse the same token and confirm replay is blocked with `403`.
4. Upload an invalid file and confirm the token is not burned unnecessarily.
5. Hit `/api/health` with the correct secret header and verify `hasLlm`, `hasStripe`, `hasRedis`, and optionally `hasPostHog` are `true`.

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

Same requirements: `TEST_SECRET` set in the deployment env, and your public IP in `TEST_ALLOWED_IPS`. Override the target with `BASE=https://your-domain.com`. Remove `TEST_SECRET` when finished to disable the endpoint.
