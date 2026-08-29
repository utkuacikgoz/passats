/**
 * Google Ads tag initialisation (AW-18417603742).
 *
 * Google publishes this as an inline block. It ships as a file here because the
 * CSP has no 'unsafe-inline' for scripts and sync-csp-hashes.js only reads
 * views/index.html — an inline copy on fifteen pages would need a hash the sync
 * script never computes, and the whole tag would be blocked without reporting
 * anything. `script-src 'self'` covers a file, and there is nothing to keep in
 * sync. See CLAUDE.md.
 *
 * Loaded before the async googletagmanager.com loader so dataLayer and gtag()
 * exist whichever arrives first; gtag.js drains the queue when it lands.
 */
window.dataLayer = window.dataLayer || [];
function gtag() { dataLayer.push(arguments); }
gtag('js', new Date());
gtag('config', 'AW-18417603742');
