/**
 * Google Tag Manager container loader (GTM-5LVMLT4Z).
 *
 * Google publishes this as an inline block. It ships as a file for the same
 * reason as gtag.js: the CSP has no 'unsafe-inline', and sync-csp-hashes.js only
 * reads views/index.html, so an inline copy across fifteen pages would be
 * blocked without reporting anything. See CLAUDE.md.
 *
 * Note for whoever adds a tag inside the GTM container later: this CSP has no
 * wildcard. A tag configured in the GTM UI that loads from an origin not named
 * in script-src, connect-src, img-src or frame-src in server.js is blocked in
 * the browser, and GTM's own preview mode will still show it as firing. If a new
 * tag reports nothing in production, that is the first thing to check.
 */
(function (w, d, s, l, i) {
  w[l] = w[l] || [];
  w[l].push({ 'gtm.start': new Date().getTime(), event: 'gtm.js' });
  var f = d.getElementsByTagName(s)[0];
  var j = d.createElement(s);
  var dl = l !== 'dataLayer' ? '&l=' + l : '';
  j.async = true;
  j.src = 'https://www.googletagmanager.com/gtm.js?id=' + i + dl;
  f.parentNode.insertBefore(j, f);
})(window, document, 'script', 'dataLayer', 'GTM-5LVMLT4Z');
