require('dotenv').config();
const express = require('express');
const multer = require('multer');
const Stripe = require('stripe');
const Anthropic = require('@anthropic-ai/sdk');
const mammoth = require('mammoth');
const pdfParse = require('pdf-parse');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// ── Config ────────────────────────────────────────────────────────────────────
const DEV_MODE = process.env.DEV_MODE === 'true';

if (!DEV_MODE) {
  const required = ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'STRIPE_PRICE_ID', 'ANTHROPIC_API_KEY'];
  const missing = required.filter(k => !process.env[k]);
  if (missing.length) {
    console.error(`Missing required env vars: ${missing.join(', ')}\nCopy .env.example to .env and fill in your keys.`);
    process.exit(1);
  }
} else {
  console.log('⚠️  DEV MODE — payments and analysis are mocked');
}

const app = express();
const stripe = DEV_MODE ? null : Stripe(process.env.STRIPE_SECRET_KEY);
const anthropic = DEV_MODE ? null : new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// In-memory session store (swap for Redis in production at scale)
const sessions = new Map();
const SESSION_TTL = 30 * 60 * 1000; // 30 minutes

// ── Middleware ─────────────────────────────────────────────────────────────────
// Stripe webhook needs raw body — must come before express.json()
app.post('/api/webhook', express.raw({ type: 'application/json' }), handleWebhook);

// Security & SEO headers
app.use((req, res, next) => {
  // Security headers (Google page experience signals)
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  // HSTS — uncomment once you have HTTPS in production
  // res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// Gzip compression — reduces HTML/CSS/JS by ~70%, improves LCP
app.use((req, res, next) => {
  const zlib = require('zlib');
  const accept = req.headers['accept-encoding'] || '';
  if (!accept.includes('gzip')) return next();

  const origSend = res.send.bind(res);
  res.send = function(body) {
    // Only compress text-based responses
    const ct = res.getHeader('content-type') || '';
    if (typeof body === 'string' || (Buffer.isBuffer(body) && /text|json|javascript|xml|svg/.test(ct))) {
      res.setHeader('Content-Encoding', 'gzip');
      res.removeHeader('Content-Length');
      zlib.gzip(body, (err, compressed) => {
        if (err) return origSend(body);
        origSend(compressed);
      });
    } else {
      origSend(body);
    }
  };
  next();
});

app.use(express.json());

// Static assets with cache headers
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '7d',               // Cache static assets for 7 days
  etag: true,                  // Enable ETag for conditional requests
  lastModified: true,
  setHeaders: (res, filePath) => {
    // HTML should revalidate (no stale content)
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
    // Immutable assets (favicon, OG image) cache aggressively
    if (/\.(png|jpg|svg|ico|woff2?)$/.test(filePath)) {
      res.setHeader('Cache-Control', 'public, max-age=2592000, immutable'); // 30 days
    }
  }
}));

// File upload config
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (_req, file, cb) => {
    const allowed = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];
    cb(null, allowed.includes(file.mimetype));
  }
});

// ── Stripe: Create Checkout Session ───────────────────────────────────────────
app.post('/api/checkout', async (req, res) => {
  if (DEV_MODE) {
    // Skip Stripe — redirect directly to success with a fake session ID
    const fakeSessionId = 'dev_' + crypto.randomBytes(12).toString('hex');
    const token = crypto.randomBytes(24).toString('hex');
    sessions.set(token, { stripeSessionId: fakeSessionId, used: false, createdAt: Date.now() });
    // Store token for verify-payment lookup
    sessions.set('dev_session:' + fakeSessionId, token);
    return res.json({ url: `${BASE_URL}/success?session_id=${fakeSessionId}` });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{
        price: process.env.STRIPE_PRICE_ID,
        quantity: 1
      }],
      success_url: `${BASE_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${BASE_URL}/?cancelled=1`,
      expires_at: Math.floor(Date.now() / 1000) + 30 * 60, // 30 min
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err.message);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// ── Stripe Webhook ────────────────────────────────────────────────────────────
async function handleWebhook(req, res) {
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
    // Create a usage token tied to this payment
    const token = crypto.randomBytes(24).toString('hex');
    sessions.set(token, {
      stripeSessionId: checkoutSession.id,
      used: false,
      createdAt: Date.now()
    });
    // Store token in Stripe metadata so the success page can retrieve it
    await stripe.checkout.sessions.update(checkoutSession.id, {
      metadata: { passats_token: token }
    }).catch(() => {}); // best-effort
  }

  res.json({ received: true });
}

// ── Verify payment & get upload token ─────────────────────────────────────────
app.get('/api/verify-payment', async (req, res) => {
  const { session_id } = req.query;
  if (!session_id) return res.status(400).json({ error: 'Missing session_id' });

  if (DEV_MODE) {
    // Look up the token we stored during checkout
    const token = sessions.get('dev_session:' + session_id);
    if (token) return res.json({ token });
    // Fallback: create a new token
    const newToken = crypto.randomBytes(24).toString('hex');
    sessions.set(newToken, { stripeSessionId: session_id, used: false, createdAt: Date.now() });
    return res.json({ token: newToken });
  }

  try {
    const checkoutSession = await stripe.checkout.sessions.retrieve(session_id);
    if (checkoutSession.payment_status !== 'paid') {
      return res.status(402).json({ error: 'Payment not completed' });
    }

    // Check if token already exists from webhook
    let token = checkoutSession.metadata?.passats_token;
    if (token && sessions.has(token)) {
      return res.json({ token });
    }

    // Fallback: webhook may not have fired yet — create token directly
    token = crypto.randomBytes(24).toString('hex');
    sessions.set(token, {
      stripeSessionId: checkoutSession.id,
      used: false,
      createdAt: Date.now()
    });
    res.json({ token });
  } catch (err) {
    console.error('Verify error:', err.message);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ── Dev mode: auto-provision a token (no checkout needed) ─────────────────────
if (DEV_MODE) {
  app.get('/api/dev-token', (req, res) => {
    const token = crypto.randomBytes(24).toString('hex');
    sessions.set(token, { stripeSessionId: 'dev', used: false, createdAt: Date.now() });
    res.json({ token });
  });
}

// ── Analyze CV ────────────────────────────────────────────────────────────────
app.post('/api/analyze', upload.single('cv'), async (req, res) => {
  const token = req.headers['x-passats-token'];
  if (!token) return res.status(401).json({ error: 'Missing token' });

  const session = sessions.get(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  if (!DEV_MODE && session.used) return res.status(403).json({ error: 'Token already used' });

  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  // Mark token as used immediately to prevent concurrent abuse
  session.used = true;

  try {
    // Extract text from the document
    let text;
    if (DEV_MODE) {
      // In dev mode, accept any file and use dummy text if extraction fails
      try { text = await extractText(req.file); } catch { text = 'Mock CV text for dev mode testing — this simulates extracted resume content for the analysis pipeline.'; }
    } else {
      text = await extractText(req.file);
    }

    if (!text || text.trim().length < 50) {
      session.used = false; // allow retry
      return res.status(422).json({ error: 'Could not extract enough text from the document. Please upload a PDF.' });
    }

    // Call Claude
    const result = await callClaude(text);
    res.json(result);
  } catch (err) {
    session.used = false; // allow retry on failure
    console.error('Analysis error:', err.message);
    res.status(500).json({ error: 'Analysis failed. Please try again.' });
  }
});

// ── Text extraction ───────────────────────────────────────────────────────────
async function extractText(file) {
  const mime = file.mimetype;

  if (mime === 'application/pdf') {
    const data = await pdfParse(file.buffer);
    return data.text;
  }

  if (mime === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
    const result = await mammoth.extractRawText({ buffer: file.buffer });
    return result.value;
  }

  if (mime === 'application/msword') {
    // .doc files — mammoth handles some, but not all
    try {
      const result = await mammoth.extractRawText({ buffer: file.buffer });
      return result.value;
    } catch {
      throw new Error('Legacy .doc format not fully supported. Please convert to PDF or .docx.');
    }
  }

  throw new Error('Unsupported file type');
}

// ── Claude API ────────────────────────────────────────────────────────────────
async function callClaude(cvText) {
  if (DEV_MODE) {
    // Return realistic mock data so the full UI can be tested
    await new Promise(r => setTimeout(r, 1500)); // simulate latency
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
        { severity: "critical", title: "No ATS-friendly section headers", detail: "Use standard headers like 'Work Experience', 'Education', 'Skills' instead of creative alternatives." },
        { severity: "critical", title: "Missing keywords", detail: "Add role-specific keywords like 'CI/CD', 'agile', 'REST API' in your experience bullets." },
        { severity: "warning", title: "Date format inconsistent", detail: "Mix of 'Jan 2023' and '01/2023'. Pick one format and stick with it." },
        { severity: "warning", title: "No measurable achievements", detail: "Quantify impact: 'Reduced deploy time by 40%' beats 'Improved deployment process'." },
        { severity: "pass", title: "Contact information present", detail: "Email and phone number are clearly visible at the top." },
        { severity: "pass", title: "Single page length", detail: "CV fits on one page — optimal for ATS and recruiters." }
      ],
      keywordsFound: ["JavaScript", "React", "Node.js", "Git", "SQL", "TypeScript"],
      keywordsMissing: ["CI/CD", "Agile/Scrum", "REST API", "Docker", "AWS", "Testing"],
      topFixes: [
        "Add 'Skills' section with exact keywords from the job posting",
        "Replace creative headers with standard ones (Work Experience, Education, Skills)",
        "Quantify at least 3 achievements with numbers or percentages",
        "Add LinkedIn profile URL to contact section",
        "Use consistent date format throughout (e.g., 'Jan 2023 – Present')"
      ]
    };
  }

  const systemPrompt = `You are an expert ATS (Applicant Tracking System) analyzer. Analyze CVs/resumes and return a detailed JSON report. Be accurate, specific, and genuinely helpful. Never invent information not present in the CV.`;

  const userPrompt = `Analyze this CV/resume as an ATS system would. Return ONLY valid JSON with this exact structure (no markdown, no explanation, just raw JSON):

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
${cvText.slice(0, 12000)}
---`;

  const message = await anthropic.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 1500,
    system: systemPrompt,
    messages: [{ role: 'user', content: userPrompt }]
  });

  const text = message.content[0].text.trim();
  const clean = text.replace(/^```json\s*/i, '').replace(/```\s*$/i, '').trim();
  return JSON.parse(clean);
}

// ── Success redirect page ─────────────────────────────────────────────────────
app.get('/success', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── SPA fallback ──────────────────────────────────────────────────────────────
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Cleanup expired sessions ──────────────────────────────────────────────────
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of sessions) {
    if (now - data.createdAt > SESSION_TTL) sessions.delete(token);
  }
}, 5 * 60 * 1000);

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`PassATS running at ${BASE_URL}`);
});
