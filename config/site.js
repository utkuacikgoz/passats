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

module.exports = {
  CANONICAL_ORIGIN,
  MAIL_DOMAIN,
  SUPPORT_EMAIL: process.env.SUPPORT_EMAIL || `support@${MAIL_DOMAIN}`,
  PRIVACY_EMAIL: process.env.PRIVACY_EMAIL || `privacy@${MAIL_DOMAIN}`,
};
