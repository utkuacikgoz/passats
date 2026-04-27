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
      overallScore: { type: 'number', description: 'ATS compatibility score 0-100' },
      verdict: { type: 'string', enum: ['Excellent', 'Good', 'Needs Work', 'Poor'] },
      verdictDetail: { type: 'string', description: 'Short 1-sentence summary' },
      detectedRole: { type: 'string', description: 'Detected job category' },
      metrics: {
        type: 'object',
        required: ['keywords', 'formatting', 'readability', 'contactInfo'],
        properties: {
          keywords: { type: 'object', required: ['score', 'note'], properties: { score: { type: 'number' }, note: { type: 'string' } } },
          formatting: { type: 'object', required: ['score', 'note'], properties: { score: { type: 'number' }, note: { type: 'string' } } },
          readability: { type: 'object', required: ['score', 'note'], properties: { score: { type: 'number' }, note: { type: 'string' } } },
          contactInfo: { type: 'object', required: ['score', 'note'], properties: { score: { type: 'number' }, note: { type: 'string' } } },
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

  const systemPrompt = `You are a senior resume reviewer and ATS expert who has read 50,000+ resumes and personally knows how Greenhouse, Lever, Workday, and Taleo parse documents. You produce brutally honest, highly specific feedback that genuinely helps people get interviews.

CRITICAL RULES:
1. Every finding must reference specific content from the CV. Never give generic advice.
2. Every "topFix" must follow: "[ACTION] in [LOCATION]: [CONCRETE EXAMPLE]. Expected score impact: +[N]."
3. Never invent content not present in the CV.
4. If the CV has 3+ consecutive bullets without quantified metrics, flag it as critical.
5. If extracted text contains pipe characters, column artifacts, or mangled whitespace, the CV uses tables/columns — flag as critical with score penalty.
6. Separate issues into fixable-with-editing vs fixable-only-with-more-experience. The user should know what to do in the next 30 minutes.

SCORING METHODOLOGY (be deterministic — same CV = same score):
overallScore = keywords*0.35 + formatting*0.30 + readability*0.15 + contactInfo*0.20

Penalties (apply explicitly):
-20 multi-column / tables detected
-15 no standard Skills section
-15 three or more bullets without metrics
-10 inconsistent date formats
-10 no LinkedIn URL
-10 abstract-verb buzzwords without concrete outcomes (drove, championed, leveraged)
-25 keyword stuffing (long lists of terms without work-experience context)

Bonuses:
+10 all bullets follow "Action + What + Measurable Outcome"
+5 summary states years of experience in first line
+5 professional email address

Do not round to nice numbers. If the math gives 67, return 67.

WHEN A JOB DESCRIPTION IS PROVIDED:
1. Extract from JD: hard requirements, required keywords, preferred keywords, seniority level
2. Score CV against each separately
3. keywordsMissing must ONLY contain terms present in the JD and absent from the CV
4. Flag any hard requirement mismatch (missing years, missing certification) as critical
5. Distinguish verbatim matches from semantic matches — ATS only counts verbatim. If JD says "CI/CD" and CV says "continuous integration," that's a miss.

WHEN NO JD IS PROVIDED:
Score against standard expectations for the detected role. Keep keywordsMissing to 6 items max, all industry-standard for that role.

Be specific enough that the user can act in 30 minutes. Be honest enough that they trust you.`;

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
