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
const required = ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'STRIPE_PRICE_ID', 'ANTHROPIC_API_KEY'];
const missing = required.filter(k => !process.env[k]);
if (missing.length) {
  console.error(`Missing required env vars: ${missing.join(', ')}\nCopy .env.example to .env and fill in your keys.`);
  process.exit(1);
}

const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// In-memory session store (swap for Redis in production at scale)
const sessions = new Map();
const SESSION_TTL = 30 * 60 * 1000; // 30 minutes

// ── Middleware ─────────────────────────────────────────────────────────────────
// Stripe webhook needs raw body — must come before express.json()
app.post('/api/webhook', express.raw({ type: 'application/json' }), handleWebhook);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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

// ── Analyze CV ────────────────────────────────────────────────────────────────
app.post('/api/analyze', upload.single('cv'), async (req, res) => {
  const token = req.headers['x-passats-token'];
  if (!token) return res.status(401).json({ error: 'Missing token' });

  const session = sessions.get(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  if (session.used) return res.status(403).json({ error: 'Token already used' });

  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  // Mark token as used immediately to prevent concurrent abuse
  session.used = true;

  try {
    // Extract text from the document
    const text = await extractText(req.file);

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
