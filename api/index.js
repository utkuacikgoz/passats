// Vercel entry point.
//
// The whole app is one Express instance in ../server.js. It lives here rather
// than at the repo root because vercel.json can only set `maxDuration` through
// the `functions` property, and `functions` cannot be combined with the legacy
// `builds` array. Routing every request into this one function (see the catch-all
// rewrite in vercel.json) is what keeps the security headers and CSP on the HTML
// responses — Vercel's static layer would serve them header-free.
module.exports = require('../server.js');
