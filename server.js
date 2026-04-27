require('dotenv').config({ quiet: true });
const express = require('express');
const compression = require('compression');
const multer = require('multer');
const Stripe = require('stripe');
const Groq = require('groq-sdk');
const mammoth = require('mammoth');
const PDFParse = require('pdf-parse/lib/pdf-parse.js');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');
const { Redis } = require('@upstash/redis');

// ── Config ────────────────────────────────────────────────────────────────────
const DEV_MODE = process.env.DEV_MODE === 'true';

if (!DEV_MODE) {
  const required = ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'STRIPE_PRICE_ID', 'GROQ_API_KEY', 'JWT_SECRET', 'UPSTASH_REDIS_REST_URL', 'UPSTASH_REDIS_REST_TOKEN'];
  const missing = required.filter(k => !process.env[k]);
  if (missing.length) {
    console.error('FATAL: Missing required env vars: ' + missing.join(', '));
    process.exit(1);
  }
}

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Dedicated JWT secret — survives Stripe key rotation
const JWT_SECRET = DEV_MODE
  ? crypto.randomBytes(32).toString('hex')
  : process.env.JWT_SECRET;

// Optional: previous secret for graceful rotation — set JWT_SECRET_PREV during rollover
const JWT_SECRET_PREV = (!DEV_MODE && process.env.JWT_SECRET_PREV) || null;

// Verify JWT with rotation support — tries current secret, falls back to previous
function verifyJwt(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch (err) {
    if (JWT_SECRET_PREV) return jwt.verify(token, JWT_SECRET_PREV);
    throw err;
  }
}

// Trust Vercel's proxy layer so req.ip is the real client IP
app.set('trust proxy', 1);

let stripe = null;
let groq = null;
let redis = null;

try {
  if (!DEV_MODE) {
    stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    groq = new Groq({ apiKey: process.env.GROQ_API_KEY });
    // Upstash Redis — atomic jti single-use. Required for token replay protection.
    redis = new Redis({
      url: process.env.UPSTASH_REDIS_REST_URL,
      token: process.env.UPSTASH_REDIS_REST_TOKEN,
    });
  }
} catch (err) {
  console.error('SDK init error:', err.message);
  process.exit(1);
}

// In dev mode only — in-memory sessions for mock tokens
const devSessions = DEV_MODE ? new Map() : null;

// ── Rate Limiter (per-instance — documented: scales with lambda count) ────────
const rateLimits = new Map();
function isRateLimited(key, maxRequests, windowMs) {
  const now = Date.now();
  // Cap map size to prevent unbounded growth on Vercel lambdas
  if (rateLimits.size > 10000) {
    const oldest = rateLimits.keys().next().value;
    rateLimits.delete(oldest);
  }
  let entry = rateLimits.get(key);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + windowMs };
  }
  entry.count++;
  rateLimits.set(key, entry);
  return entry.count > maxRequests;
}

// ── Request ID middleware ─────────────────────────────────────────────────────
app.use((req, _res, next) => {
  req.requestId = crypto.randomUUID();
  next();
});

// ── Middleware ─────────────────────────────────────────────────────────────────
// Stripe webhook needs raw body — registered before express.json() and security headers.
// Intentional: webhook is machine-to-machine (Stripe-signed), CSP/HSTS not needed.
app.post('/api/webhook', express.raw({ type: 'application/json', limit: '1mb' }), handleWebhook);

// Security & SEO headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  // CSP: connect-src 'self' is sufficient — all Stripe calls are server-side redirects.
  // If Stripe Elements (js.stripe.com) is ever added, update script-src + frame-src.
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' fonts.googleapis.com",
    "font-src fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self'",
  ].join('; '));
  next();
});

// No-cache on API responses — prevent browsers/proxies from caching tokens/data
app.use('/api', (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, private');
  next();
});

// Gzip compression
app.use(compression());

app.use(express.json({ limit: '50kb' }));

// Static assets with cache headers
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '7d',
  etag: true,
  lastModified: true,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
    if (/\.(png|jpg|svg|ico|woff2?)$/.test(filePath)) {
      res.setHeader('Cache-Control', 'public, max-age=2592000, immutable');
    }
  }
}));

// ── Health check (gated behind secret header) ─────────────────────────────────
app.get('/api/health', (req, res) => {
  if (req.headers['x-health-secret'] !== process.env.HEALTH_SECRET) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.json({
    status: 'ok',
    devMode: DEV_MODE,
    hasStripe: !!stripe,
    hasGroq: !!groq,
    hasRedis: !!redis,
  });
});

// ── File upload config ────────────────────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, fieldSize: 20000, fields: 5 },
  fileFilter: (_req, file, cb) => {
    const allowed = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];
    cb(null, allowed.includes(file.mimetype));
  }
});

// Magic-byte validation — don't trust client mimetype alone
function validateMagicBytes(buffer, mimetype) {
  if (buffer.length < 4) return false;
  if (mimetype === 'application/pdf') {
    return buffer.slice(0, 5).toString() === '%PDF-';
  }
  if (mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
    // PK header + check for word/document.xml signature in zip central directory
    if (buffer[0] !== 0x50 || buffer[1] !== 0x4B) return false;
    // Look for 'word/' string in first 2KB — present in all valid .docx files
    const header = buffer.slice(0, Math.min(buffer.length, 2048)).toString('binary');
    return header.includes('word/');
  }
  if (mimetype === 'application/msword') {
    return buffer[0] === 0xD0 && buffer[1] === 0xCF; // DOC compound file
  }
  return false;
}

// ── CSRF check for state-changing endpoints ───────────────────────────────────
function checkOrigin(req, res) {
  if (DEV_MODE) return true;
  const origin = req.headers['origin'];
  // All modern browsers send Origin on POST — reject if absent
  if (!origin) {
    res.status(403).json({ error: 'Forbidden' });
    return false;
  }
  const allowed = new URL(BASE_URL).origin;
  if (origin !== allowed) {
    res.status(403).json({ error: 'Forbidden' });
    return false;
  }
  return true;
}

// ── Atomic jti single-use via Redis SET NX ────────────────────────────────────
async function claimToken(jti) {
  if (DEV_MODE) return true; // dev mode uses in-memory Map
  // SET NX with 30-min TTL — returns 'OK' only if key didn't exist
  const result = await redis.set(`passats:jti:${jti}`, '1', { nx: true, ex: 1800 });
  return result === 'OK';
}

// ── Stripe: Create Checkout Session ───────────────────────────────────────────
app.post('/api/checkout', async (req, res) => {
  if (!checkOrigin(req, res)) return;

  const ip = req.ip;
  if (isRateLimited('checkout:' + ip, 10, 60000)) {
    return res.status(429).json({ error: 'Too many requests. Try again in a minute.' });
  }

  if (DEV_MODE) {
    const fakeSessionId = 'dev_' + crypto.randomBytes(12).toString('hex');
    const token = jwt.sign({ sessionId: fakeSessionId, jti: crypto.randomUUID() }, JWT_SECRET, { expiresIn: '30m' });
    if (devSessions) devSessions.set(fakeSessionId, { token, used: false });
    return res.json({ url: `${BASE_URL}/success?session_id=${fakeSessionId}` });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      success_url: `${BASE_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${BASE_URL}/?cancelled=1`,
      expires_at: Math.floor(Date.now() / 1000) + 30 * 60,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error(`[${req.requestId}] Checkout error:`, err.message);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// ── Stripe Webhook ────────────────────────────────────────────────────────────
async function handleWebhook(req, res) {
  if (DEV_MODE) return res.json({ received: true });

  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature failed:', err.message);
    return res.status(400).send('Webhook Error');
  }

  if (event.type === 'checkout.session.completed') {
    const checkoutSession = event.data.object;
    // Idempotency: if webhook re-fires (Stripe retries on 5xx), don't overwrite existing token
    if (checkoutSession.metadata?.passats_token) {
      return res.json({ received: true });
    }
    const token = jwt.sign(
      { sessionId: checkoutSession.id, jti: crypto.randomUUID() },
      JWT_SECRET,
      { expiresIn: '30m' }
    );
    await stripe.checkout.sessions.update(checkoutSession.id, {
      metadata: { passats_token: token }
    }).catch(() => {});
  }

  res.json({ received: true });
}

// ── Verify payment & get upload token ─────────────────────────────────────────
app.get('/api/verify-payment', async (req, res) => {
  const ip = req.ip;
  if (isRateLimited('verify:' + ip, 20, 60000)) {
    return res.status(429).json({ error: 'Too many requests. Try again in a minute.' });
  }

  const { session_id } = req.query;
  if (!session_id) return res.status(400).json({ error: 'Missing session_id' });

  if (DEV_MODE) {
    const devEntry = devSessions ? devSessions.get(session_id) : null;
    if (devEntry && devEntry.token) return res.json({ token: devEntry.token });
    const newToken = jwt.sign({ sessionId: session_id, jti: crypto.randomUUID() }, JWT_SECRET, { expiresIn: '30m' });
    return res.json({ token: newToken });
  }

  try {
    const checkoutSession = await stripe.checkout.sessions.retrieve(session_id);
    if (checkoutSession.payment_status !== 'paid') {
      return res.status(402).json({ error: 'Payment not completed' });
    }

    // Cap token refresh window — session must be < 1 hour old
    const sessionAgeMs = Date.now() - (checkoutSession.created * 1000);
    if (sessionAgeMs > 60 * 60 * 1000) {
      return res.status(410).json({ error: 'Session expired. Please purchase again.' });
    }

    // Check if token already exists from webhook
    let token = checkoutSession.metadata?.passats_token;
    if (token) {
      try {
        verifyJwt(token);
        return res.json({ token });
      } catch {
        // Token expired or invalid — create new one below
      }
    }

    // Webhook may not have fired yet — create token directly
    token = jwt.sign(
      { sessionId: checkoutSession.id, jti: crypto.randomUUID() },
      JWT_SECRET,
      { expiresIn: '30m' }
    );
    await stripe.checkout.sessions.update(checkoutSession.id, {
      metadata: { passats_token: token }
    }).catch(() => {});
    res.json({ token });
  } catch (err) {
    console.error(`[${req.requestId}] Verify error:`, err.message);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ── Dev mode: auto-provision token (only with explicit DEV_MODE=true) ─────────
if (DEV_MODE) {
  if (process.env.VERCEL) {
    console.error('FATAL: DEV_MODE=true is not allowed on Vercel. Aborting.');
    process.exit(1);
  }
  console.log('\u26a0\ufe0f  DEV MODE \u2014 payments and analysis are mocked');
  app.get('/api/dev-token', (req, res) => {
    const token = jwt.sign({ sessionId: 'dev', jti: crypto.randomUUID() }, JWT_SECRET, { expiresIn: '30m' });
    if (devSessions) devSessions.set('dev', { token, used: false });
    res.json({ token });
  });
}

// ── Owner test token — bypass payment in production for smoke testing ─────────
app.get('/api/test-token', (req, res) => {
  const secret = process.env.TEST_SECRET;
  if (!secret || req.headers['x-test-secret'] !== secret) {
    return res.status(404).json({ error: 'Not found' });
  }
  const token = jwt.sign(
    { sessionId: 'test_' + crypto.randomUUID(), jti: crypto.randomUUID() },
    JWT_SECRET,
    { expiresIn: '30m' }
  );
  res.json({ token });
});

// ── Pre-multer auth — origin + rate limit + JWT verify before file upload ─────
function analyzeAuth(req, res, next) {
  if (!checkOrigin(req, res)) return;
  if (isRateLimited('analyze:' + req.ip, 10, 60000)) {
    return res.status(429).json({ error: 'Too many requests. Try again in a minute.' });
  }
  const tokenHeader = req.headers['x-passats-token'];
  if (!tokenHeader) return res.status(401).json({ error: 'Missing token' });
  try {
    req.tokenPayload = verifyJwt(tokenHeader);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── Analyze CV ────────────────────────────────────────────────────────────────
app.post('/api/analyze', analyzeAuth, upload.single('cv'), async (req, res) => {
  const reqId = req.requestId;
  const tokenPayload = req.tokenPayload;

  // Dev mode: check in-memory
  if (DEV_MODE) {
    const devEntry = devSessions?.get(tokenPayload.sessionId) || devSessions?.get('dev');
    if (devEntry?.used) return res.status(403).json({ error: 'Token already used (dev)' });
    if (devEntry) devEntry.used = true;
  }

  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  // Magic byte validation — reject before claiming token so user isn't burned on bad file
  if (!validateMagicBytes(req.file.buffer, req.file.mimetype)) {
    console.warn(`[${reqId}] Magic byte mismatch: ${req.file.mimetype}`);
    return res.status(400).json({ error: 'File content does not match its type. Please upload a valid PDF or DOCX.' });
  }

  // Atomic single-use via Redis SET NX on jti — after all pre-validation gates
  let claimed;
  try {
    claimed = await claimToken(tokenPayload.jti);
  } catch (err) {
    console.error(`[${reqId}] Redis claimToken failed:`, err.message);
    return res.status(503).json({ error: `Service temporarily unavailable. Quote ref ${reqId}.` });
  }
  if (!claimed) {
    console.warn(`[${reqId}] Token replay blocked: jti=${tokenPayload.jti}`);
    return res.status(403).json({ error: 'Token already used' });
  }

  try {
    let text;
    if (DEV_MODE) {
      try { text = await extractText(req.file); } catch { /* fall through */ }
      if (!text || text.trim().length < 50) {
        text = 'John Doe — Software Engineer with 5 years experience in JavaScript, React, Node.js, SQL, Git. Built scalable APIs and led CI/CD adoption.';
      }
    } else {
      text = await extractText(req.file);
    }

    if (!text || text.trim().length < 50) {
      // Image-based PDF / insufficient text — release token (not adversarial, user mistake)
      if (redis && tokenPayload.jti) {
        await redis.del(`passats:jti:${tokenPayload.jti}`).catch(delErr => {
          console.error(`[${reqId}] CRITICAL: Redis del failed — token permanently burned for jti=${tokenPayload.jti}:`, delErr.message);
        });
      }
      console.warn(`[${reqId}] Insufficient text extracted: ${(text || '').length} chars`);
      return res.status(422).json({ error: `Could not extract enough text. Please upload a text-based PDF or DOCX. If this persists, quote ref ${reqId}.` });
    }

    // Job description from multipart form field
    const jobDescription = req.body?.jobDescription || '';
    console.log(`[${reqId}] Calling Claude for analysis...`);
    const result = await callClaude(text, jobDescription);
    console.log(`[${reqId}] Analysis complete: score=${result.overallScore}`);
    res.json(result);
  } catch (err) {
    // Password-protected PDF — release token (user mistake, not adversarial)
    if (err.message === 'PDF_PASSWORD_PROTECTED') {
      if (redis && tokenPayload.jti) {
        await redis.del(`passats:jti:${tokenPayload.jti}`).catch(() => {});
      }
      return res.status(422).json({ error: `This PDF is password-protected. Please remove the password and re-upload. Quote ref ${reqId}.` });
    }

    // Track retries per jti — burn permanently after 3 to prevent timeout/error abuse
    if (redis && tokenPayload.jti) {
      const retryKey = `passats:retry:${tokenPayload.jti}`;
      const retries = await redis.incr(retryKey).catch(() => 999);
      if (retries <= 3) {
        await redis.expire(retryKey, 1800).catch(() => {});
        await redis.del(`passats:jti:${tokenPayload.jti}`).catch(delErr => {
          console.error(`[${reqId}] CRITICAL: Redis del failed — token permanently burned for jti=${tokenPayload.jti}:`, delErr.message);
        });
        console.error(`[${reqId}] Analysis error (retry ${retries}/3):`, err.message);
        return res.status(500).json({ error: `Analysis failed. Please try again (${retries}/3). If this persists, quote ref ${reqId}.` });
      }
      console.error(`[${reqId}] Analysis error — retries exhausted, token burned:`, err.message);
      return res.status(500).json({ error: `Analysis failed. Maximum retries exceeded. Quote ref ${reqId}.` });
    }
    console.error(`[${reqId}] Analysis error:`, err.message);
    res.status(500).json({ error: `Analysis failed. Please try again. If this persists, quote ref ${reqId}.` });
  }
});

// ── Text extraction with 15s timeout ──────────────────────────────────────────
async function extractText(file) {
  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('Document parsing timed out')), 15000)
  );

  const parse = (async () => {
    const mime = file.mimetype;
    if (mime === 'application/pdf') {
      try {
        const data = await PDFParse(file.buffer);
        return data.text;
      } catch (err) {
        if (err.message && /password|encrypted/i.test(err.message)) {
          throw new Error('PDF_PASSWORD_PROTECTED');
        }
        throw err;
      }
    }
    if (mime === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
        mime === 'application/msword') {
      const result = await mammoth.extractRawText({ buffer: file.buffer });
      return result.value;
    }
    throw new Error('Unsupported file type');
  })();

  return Promise.race([parse, timeout]);
}

// ── Claude API (tool use with JSON schema — guarantees valid JSON) ─────────────
const ATS_RESULT_SCHEMA = {
  name: 'ats_report',
  description: 'ATS compatibility analysis report for a CV/resume',
  input_schema: {
    type: 'object',
    required: ['overallScore', 'verdict', 'verdictDetail', 'detectedRole', 'metrics', 'issues', 'keywordsFound', 'keywordsMissing', 'topFixes'],
    properties: {
      overallScore: { type: 'number', minimum: 0, maximum: 100, description: 'ATS compatibility score, integer between 0 and 100 (e.g. 67, NOT 0.67)' },
      verdict: { type: 'string', enum: ['Excellent', 'Good', 'Needs Work', 'Poor'] },
      verdictDetail: { type: 'string', description: 'Short 1-sentence summary' },
      detectedRole: { type: 'string', description: 'Detected job category' },
      metrics: {
        type: 'object',
        required: ['keywords', 'formatting', 'readability', 'contactInfo'],
        properties: {
          keywords: { type: 'object', required: ['score', 'note'], properties: { score: { type: 'number', minimum: 0, maximum: 100, description: 'Integer 0-100, e.g. 72' }, note: { type: 'string' } } },
          formatting: { type: 'object', required: ['score', 'note'], properties: { score: { type: 'number', minimum: 0, maximum: 100, description: 'Integer 0-100, e.g. 72' }, note: { type: 'string' } } },
          readability: { type: 'object', required: ['score', 'note'], properties: { score: { type: 'number', minimum: 0, maximum: 100, description: 'Integer 0-100, e.g. 72' }, note: { type: 'string' } } },
          contactInfo: { type: 'object', required: ['score', 'note'], properties: { score: { type: 'number', minimum: 0, maximum: 100, description: 'Integer 0-100, e.g. 72' }, note: { type: 'string' } } },
        }
      },
      issues: {
        type: 'array',
        items: {
          type: 'object', required: ['severity', 'title', 'detail'],
          properties: {
            severity: { type: 'string', enum: ['critical', 'warning', 'pass'] },
            title: { type: 'string' },
            detail: { type: 'string' },
          }
        }
      },
      keywordsFound: { type: 'array', items: { type: 'string' }, maxItems: 8, description: 'Max 8 keywords found' },
      keywordsMissing: { type: 'array', items: { type: 'string' }, maxItems: 6, description: 'Max 6 missing keywords' },
      topFixes: { type: 'array', items: { type: 'string' }, maxItems: 5, description: '5 actionable fix strings' },
    }
  }
};

async function callClaude(cvText, jobDescription) {
  if (DEV_MODE) {
    await new Promise(r => setTimeout(r, 1500));
    return {
      overallScore: 72,
      verdict: "Needs Work",
      verdictDetail: "Your CV has solid experience but ATS parsers will struggle with the formatting.",
      detectedRole: "Software Engineer",
      metrics: {
        keywords: { score: 65, note: "Missing some industry-standard keywords for this role." },
        formatting: { score: 78, note: "Clean layout but consider removing tables and columns." },
        readability: { score: 80, note: "Good sentence length and structure overall." },
        contactInfo: { score: 90, note: "Email and phone detected. Add LinkedIn URL." }
      },
      issues: [
        { severity: "critical", title: "No ATS-friendly section headers", detail: "Use standard headers like 'Work Experience', 'Education', 'Skills'." },
        { severity: "critical", title: "Missing keywords", detail: "Add role-specific keywords like 'CI/CD', 'agile', 'REST API'." },
        { severity: "warning", title: "Date format inconsistent", detail: "Mix of 'Jan 2023' and '01/2023'. Pick one format." },
        { severity: "warning", title: "No measurable achievements", detail: "Quantify impact: 'Reduced deploy time by 40%' beats 'Improved deployment process'." },
        { severity: "pass", title: "Contact information present", detail: "Email and phone number are clearly visible at the top." },
        { severity: "pass", title: "Single page length", detail: "CV fits on one page \u2014 optimal for ATS and recruiters." }
      ],
      keywordsFound: ["JavaScript", "React", "Node.js", "Git", "SQL", "TypeScript"],
      keywordsMissing: ["CI/CD", "Agile/Scrum", "REST API", "Docker", "AWS", "Testing"],
      topFixes: [
        "Add 'Skills' section with exact keywords from the job posting",
        "Replace creative headers with standard ones (Work Experience, Education, Skills)",
        "Quantify at least 3 achievements with numbers or percentages",
        "Add LinkedIn profile URL to contact section",
        "Use consistent date format throughout (e.g., 'Jan 2023 \u2013 Present')"
      ]
    };
  }

  const jdContext = jobDescription && jobDescription.trim()
    ? `\n\nThe candidate is applying for a role with this job description:\n---\n${jobDescription.slice(0, 8000)}\n---\nScore keyword relevance against this specific job description.`
    : '\nNo specific job description provided. Score keywords based on the detected role and general industry expectations.';

  const systemPrompt = `You are a brutally honest ATS expert and senior recruiter who has reviewed 50,000+ resumes for companies using Greenhouse, Lever, Workday, and Taleo. Your job is to give the most accurate, specific, actionable ATS analysis possible. You do not flatter candidates.

ABSOLUTE RULES — violating these makes the analysis worthless:
1. Every issue title and detail MUST reference specific text, section names, or bullet points from the CV. "Your CV lacks metrics" is banned. "3 of 4 bullets in your Revolut section use abstract verbs (led, drove, managed) with no numbers" is correct.
2. Every topFix MUST follow exactly: "[ACTION] in [SECTION NAME]: [CONCRETE EXAMPLE FROM THE CV]. Expected score impact: +[N] points." The example MUST be reworded real content from the CV — never invent numbers, percentages, or outcomes that are not in the CV.
3. Never suggest keywords that are not standard for the detected role. A Product Owner CV should NOT have "Cybersecurity" or "Machine Learning" as missing keywords unless those are in a job description.
4. Always return exactly 5 topFixes. Always return at least 5 issues. At least 1 issue must be critical if any penalty applies.
5. Never invent content not in the CV. Never give generic advice. CVs do not have CTAs, calls-to-action, or marketing copy — do not suggest adding them.
6. Severity rules: critical = directly causes ATS rejection or major score penalty; warning = hurts score but won't cause rejection; pass = done correctly.

SCORING — ALL SCORES ARE INTEGERS 0-100 (e.g. 67, never 0.67):
overallScore = round(keywords*0.35 + formatting*0.30 + readability*0.15 + contactInfo*0.20)

PENALTIES — apply each that is true, show your working:
-20 if multi-column layout or tables detected (pipe chars, irregular whitespace)
-15 if no dedicated Skills section exists
-15 if 3+ consecutive bullets lack any quantified metric
-10 if date formats are inconsistent across sections
-10 if no LinkedIn URL AND no personal website/portfolio URL in contact section
-10 for each paragraph of abstract buzzwords without measurable outcomes (drove, championed, spearheaded, leveraged)

BONUSES — apply each that is true:
+10 if every bullet follows Action + What + Measurable Outcome
+5 if summary/profile states total years of experience explicitly
+5 if email address is professional (firstname.lastname@domain)
+5 if personal website, portfolio, or GitHub URL is present in addition to LinkedIn

ROLE-SPECIFIC KEYWORD GUIDANCE (use when no JD provided):
- Software Engineer: TypeScript, React/Vue/Angular, Node.js, CI/CD, Docker, AWS/GCP, REST API, Testing, Git, Agile
- Product Owner/PM: Product Roadmap, OKR, A/B Testing, Stakeholder Management, Go-to-market, Sprint Planning, KPI, User Story, Agile/Scrum, Discovery
- Data Analyst/Scientist: SQL, Python, Tableau/Power BI, A/B Testing, ETL, Statistical Analysis, Dashboard, Regression, Pandas
- Marketing: SEO, SEM, Conversion Rate, Google Analytics, CRM, Campaign Management, A/B Testing, Funnel, CAC, LTV
- Finance: Financial Modelling, Excel, P&L, Variance Analysis, FP&A, IFRS/GAAP, Forecasting, Budgeting, Power BI
Only suggest keywords that are industry-standard for the detected role.

WHEN A JOB DESCRIPTION IS PROVIDED:
1. Extract hard requirements, required keywords, seniority signals
2. keywordsMissing must ONLY list terms from the JD absent in the CV — never invent
3. Verbatim matching only — "CI/CD" ≠ "continuous integration" for ATS
4. Flag every hard requirement mismatch (missing cert, years, degree) as critical

WHEN NO JD IS PROVIDED:
Use the role-specific keyword list above. keywordsMissing max 6 items, all must be standard for the role.

verdictDetail must be 1 specific sentence that names something concrete from the CV.
Be honest enough that the user trusts you. Be specific enough they can act in 30 minutes.`;

  // Slice at newline boundary to avoid truncating mid-bullet
  const maxLen = 40000;
  const cvSlice = cvText.length <= maxLen ? cvText : cvText.slice(0, (cvText.lastIndexOf('\n', maxLen) + 1) || maxLen);

  const userPrompt = `Analyze this CV/resume as an ATS system would.${jdContext}

Use the ats_report function to return your analysis. Be honest and specific.

Here is the CV text:

---
${cvSlice}
---`;

  const response = await groq.chat.completions.create({
    model: 'llama-3.3-70b-versatile',
    max_tokens: 2000,
    temperature: 0.1,
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt }
    ],
    tools: [{
      type: 'function',
      function: {
        name: ATS_RESULT_SCHEMA.name,
        description: ATS_RESULT_SCHEMA.description,
        parameters: ATS_RESULT_SCHEMA.input_schema,
      }
    }],
    tool_choice: { type: 'function', function: { name: 'ats_report' } },
  });

  const toolCall = response.choices?.[0]?.message?.tool_calls?.[0];
  if (!toolCall || !toolCall.function?.arguments) {
    console.error('Groq did not return a tool call');
    throw new Error('Analysis returned invalid format. Please try again.');
  }

  let result;
  try {
    result = JSON.parse(toolCall.function.arguments);
  } catch {
    console.error('Groq tool call arguments were not valid JSON');
    throw new Error('Analysis returned invalid format. Please try again.');
  }

  // Normalize scores: if Groq returned 0-1 decimals instead of 0-100, fix them
  const normalizeScore = s => (typeof s === 'number' && s > 0 && s <= 1) ? Math.round(s * 100) : Math.round(s);
  if (result.overallScore !== undefined) result.overallScore = normalizeScore(result.overallScore);
  if (result.metrics) {
    for (const key of ['keywords', 'formatting', 'readability', 'contactInfo']) {
      if (result.metrics[key]?.score !== undefined) {
        result.metrics[key].score = normalizeScore(result.metrics[key].score);
      }
    }
  }

  return result;
}

// ── Privacy / Terms pages ─────────────────────────────────────────────────────
app.get('/privacy', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});
app.get('/terms', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'terms.html'));
});

// ── Success redirect page ─────────────────────────────────────────────────────
app.get('/success', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── SPA fallback ──────────────────────────────────────────────────────────────
app.get('{*path}', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Cleanup (rate limit entries — non-Vercel only) ────────────────────────────
if (!process.env.VERCEL) {
  const cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of rateLimits) {
      if (now > entry.resetAt) rateLimits.delete(key);
    }
  }, 60000);
  cleanupTimer.unref(); // Don't keep process alive for cleanup
}

// ── Start ─────────────────────────────────────────────────────────────────────
if (process.env.VERCEL) {
  module.exports = app;
} else if (require.main === module) {
  app.listen(PORT, () => console.log(`PassATS running at ${BASE_URL}`));
} else {
  // Required as a module (e.g. tests)
  module.exports = app;
}
