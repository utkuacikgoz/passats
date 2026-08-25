'use strict';

// The canonical identity of the site, in one place.
//
// The domain was hardcoded in fifteen literals across HTML canonicals, Open
// Graph tags, three JSON-LD blocks, robots.txt, llms.txt, the sitemap and the
// printed report footer. Moving from passats.vercel.app to passats.pro meant
// finding all of them, and missing one points a crawler or a customer at a host
// that is not yours any more.
//
// These values are the source of truth. `npm run sync:domain` rewrites the
// static files from them, and CI fails if the committed output has drifted.
// Override CANONICAL_ORIGIN to stage another move without editing this file.
const CANONICAL_ORIGIN = (process.env.CANONICAL_ORIGIN || 'https://passats.pro').replace(/\/+$/, '');
const MAIL_DOMAIN = new URL(CANONICAL_ORIGIN).hostname.replace(/^www\./, '');

// Trader identity. EU and UK consumer law requires a paid service to name the
// legal entity behind it, so these belong on the legal pages rather than in a
// footer somewhere. REGISTERED_ADDRESS is env-supplied and deliberately has no
// default: an invented address on a legal page is worse than an absent one.
const LEGAL_ENTITY = process.env.LEGAL_ENTITY || 'Bosphorus Elevate LLC';
const JURISDICTION = process.env.JURISDICTION || 'Delaware, United States';
const REGISTERED_ADDRESS = process.env.REGISTERED_ADDRESS || '';

module.exports = {
  CANONICAL_ORIGIN,
  MAIL_DOMAIN,
  LEGAL_ENTITY,
  JURISDICTION,
  REGISTERED_ADDRESS,
  SUPPORT_EMAIL: process.env.SUPPORT_EMAIL || `support@${MAIL_DOMAIN}`,
  PRIVACY_EMAIL: process.env.PRIVACY_EMAIL || `privacy@${MAIL_DOMAIN}`,
};
