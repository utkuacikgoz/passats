require('dotenv').config();
const express = require('express');
const compression = require('compression');
const multer = require('multer');
const Stripe = require('stripe');
const Anthropic = require('@anthropic-ai/sdk');
const mammoth = require('mammoth');
const pdfParse = require('pdf-parse');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');

// ── Config ────────────────────────────────────────────────────────────────────
const DEV_MODE = process.env.DEV_MODE === 'true';

if (!DEV_MODE) {
  const required = ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'STRIPE_PRICE_ID', 'ANTHROPIC_API_KEY'];
  const missing = required.filter(k => !process.env[k]);
  if (missing.length) {
    console.error('FATAL: Missing required env vars: ' + missing.join(', '));
    process.exit(1);
  }
} else {
  console.log('\u26a0\ufe0f  DEV MODE \u2014 payments and analysis are mocked');
}

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// JWT secret — derived from STRIPE_SECRET_KEY in prod, random in dev
const JWT_SECRET = DEV_MODE
  ? crypto.randomBytes(32).toString('hex')
  : crypto.createHash('sha256').update(process.env.STRIPE_SECRET_KEY).digest('hex');

let stripe = null;
let anthropic = null;

try {
  if (!DEV_MODE) {
    stripe = Stripe(process.env.STRIPE_SECRET_KEY);
    anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  }
} catch (err) {
  console.error('SDK init error:', err.message);
  process.exit(1);
}

// In dev mode only — in-memory sessions for mock tokens
const devSessions = DEV_MODE ? new Map() : null;

// ── Rate Limiter (per-instance, sufficient for single-region Vercel) ──────────
const rateLimits = new Map();
function isRateLimited(key, maxRequests, windowMs) {
  const now = Date.now();
  let entry = rateLimits.get(key);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + windowMs };
  }
  entry.count++;
  rateLimits.set(key, entry);
  return entry.count > maxRequests;
}

// ── Middleware ─────────────────────────────────────────────────────────────────
// Stripe webhook needs raw body — must come before express.json()
app.post('/api/webhook', express.raw({ type: 'application/json' }), handleWebhook);

// Security & SEO headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' fonts.googleapis.com",
    "font-src fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self' api.stripe.com",
  ].join('; '));
  next();
});

// Gzip compression (replaces hand-rolled middleware)
app.use(compression());

app.use(express.json());

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
    hasAnthropic: !!anthropic,
  });
});

// ── File upload config ────────────────────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
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
    return buffer[0] === 0x50 && buffer[1] === 0x4B; // PK (zip/docx)
  }
  if (mimetype === 'application/msword') {
    return buffer[0] === 0xD0 && buffer[1] === 0xCF; // DOC compound file
  }
  return false;
}

// ── Stripe: Create Checkout Session ───────────────────────────────────────────
app.post('/api/checkout', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.ip;
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
    console.error('Checkout error:', err.message);
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
  const ip = req.headers['x-forwarded-for'] || req.ip;
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

    // Check if token already exists from webhook
    let token = checkoutSession.metadata?.passats_token;
    if (token) {
      try {
        jwt.verify(token, JWT_SECRET);
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
    console.error('Verify error:', err.message);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ── Dev mode: auto-provision token (only with explicit DEV_MODE=true) ─────────
if (DEV_MODE) {
  app.get('/api/dev-token', (req, res) => {
    const token = jwt.sign({ sessionId: 'dev', jti: crypto.randomUUID() }, JWT_SECRET, { expiresIn: '30m' });
    if (devSessions) devSessions.set('dev', { token, used: false });
    res.json({ token });
  });
}

// ── Analyze CV ────────────────────────────────────────────────────────────────
app.post('/api/analyze', upload.single('cv'), async (req, res) => {
  const tokenHeader = req.headers['x-passats-token'];
  if (!tokenHeader) return res.status(401).json({ error: 'Missing token' });

  // Verify JWT
  let tokenPayload;
  try {
    tokenPayload = jwt.verify(tokenHeader, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  // Check if token was already used (via Stripe metadata — serverless-safe)
  if (!DEV_MODE) {
    try {
      const session = await stripe.checkout.sessions.retrieve(tokenPayload.sessionId);
      if (session.metadata?.passats_used === 'true') {
        return res.status(403).json({ error: 'Token already used' });
      }
      // Mark as used immediately to narrow race window
      await stripe.checkout.sessions.update(tokenPayload.sessionId, {
        metadata: { ...session.metadata, passats_used: 'true' }
      });
    } catch (err) {
      console.error('Token verification via Stripe failed:', err.message);
      return res.status(401).json({ error: 'Token verification failed' });
    }
  } else {
    const devEntry = devSessions?.get(tokenPayload.sessionId) || devSessions?.get('dev');
    if (devEntry?.used) return res.status(403).json({ error: 'Token already used (dev)' });
    if (devEntry) devEntry.used = true;
  }

  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  // Magic byte validation
  if (!validateMagicBytes(req.file.buffer, req.file.mimetype)) {
    if (!DEV_MODE) {
      await stripe.checkout.sessions.update(tokenPayload.sessionId, {
        metadata: { passats_used: 'false' }
      }).catch(() => {});
    }
    return res.status(400).json({ error: 'File content does not match its type. Please upload a valid PDF or DOCX.' });
  }

  try {
    let text;
    if (DEV_MODE) {
      try { text = await extractText(req.file); } catch { text = 'Mock CV text for dev mode testing.'; }
    } else {
      text = await extractText(req.file);
    }

    if (!text || text.trim().length < 50) {
      if (!DEV_MODE) {
        await stripe.checkout.sessions.update(tokenPayload.sessionId, {
          metadata: { passats_used: 'false' }
        }).catch(() => {});
      }
      return res.status(422).json({ error: 'Could not extract enough text. Please upload a text-based PDF.' });
    }

    // Job description from multipart form field
    const jobDescription = req.body?.jobDescription || '';
    const result = await callClaude(text, jobDescription);
    res.json(result);
  } catch (err) {
    // Revert used flag on failure
    if (!DEV_MODE) {
      await stripe.checkout.sessions.update(tokenPayload.sessionId, {
        metadata: { passats_used: 'false' }
      }).catch(() => {});
    }
    console.error('Analysis error:', err.message);
    res.status(500).json({ error: 'Analysis failed. Please try again.' });
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
      const data = await pdfParse(file.buffer);
      return data.text;
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

// ── Claude API ────────────────────────────────────────────────────────────────
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

  const systemPrompt = `You are an expert ATS (Applicant Tracking System) analyzer. Analyze CVs/resumes and return a detailed JSON report. Be accurate, specific, and genuinely helpful. Never invent information not present in the CV.

Score calibration guide:
- A CV with no skills section, tables, and multi-column layout scores around 40.
- A CV with standard sections but generic bullets and some formatting issues scores around 60.
- A clean one-column CV with all standard sections, quantified bullets, and relevant keywords scores around 85.
- A perfect ATS-optimized CV with tailored keywords, clean formatting, and strong metrics scores 90+.`;

  const userPrompt = `Analyze this CV/resume as an ATS system would.${jdContext}

Return ONLY valid JSON with this exact structure (no markdown, no explanation, just raw JSON):

{
  "overallScore": <number 0-100>,
  "verdict": <"Excellent" | "Good" | "Needs Work" | "Poor">,
  "verdictDetail": <short 1-sentence summary>,
  "detectedRole": <detected job category>,
  "metrics": {
    "keywords": { "score": <0-100>, "note": <1 sentence> },
    "formatting": { "score": <0-100>, "note": <1 sentence> },
    "readability": { "score": <0-100>, "note": <1 sentence> },
    "contactInfo": { "score": <0-100>, "note": <1 sentence> }
  },
  "issues": [
    { "severity": <"critical"|"warning"|"pass">, "title": <short>, "detail": <1-2 sentences> }
  ],
  "keywordsFound": [<max 8 keyword strings>],
  "keywordsMissing": [<max 6 missing keyword strings>],
  "topFixes": [<5 actionable fix strings>]
}

Be honest and specific. Here is the CV text:

---
${cvText.slice(0, 20000)}
---`;

  const message = await anthropic.messages.create({
    model: 'claude-sonnet-4-6',
    max_tokens: 1500,
    system: systemPrompt,
    messages: [{ role: 'user', content: userPrompt }]
  });

  const text = message.content[0].text.trim();
  const clean = text.replace(/^```json\s*/i, '').replace(/```\s*$/i, '').trim();
  try {
    return JSON.parse(clean);
  } catch (parseErr) {
    console.error('Claude returned invalid JSON:', clean.slice(0, 200));
    throw new Error('Analysis returned invalid format. Please try again.');
  }
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
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Cleanup (rate limit entries) ──────────────────────────────────────────────
if (!process.env.VERCEL) {
  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of rateLimits) {
      if (now > entry.resetAt) rateLimits.delete(key);
    }
  }, 60000);
}

// ── Start ─────────────────────────────────────────────────────────────────────
if (process.env.VERCEL) {
  module.exports = app;
} else {
  app.listen(PORT, () => console.log(`PassATS running at ${BASE_URL}`));
}
