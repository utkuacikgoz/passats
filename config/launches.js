'use strict';

// Every place PassATS is listed, in the order the landing page shows them.
//
// This is the only list to edit. `npm run sync:launches` (part of sync:seo)
// rebuilds the moving "featured on" band in views/index.html and the
// Organization `sameAs` in its JSON-LD from it, and CI fails if the committed
// page has drifted.
//
// Add a launch only once its page is live. The band says "Featured on", so a
// listing that does not exist yet would be a false claim on the page that takes
// the money.
//
//   name   what the band shows, e.g. 'Hacker News'
//   url    the public listing or launch page
//   label  optional lead-in, defaults to 'Featured on'
const LAUNCHES = [
  { name: 'Product Hunt', url: 'https://www.producthunt.com/products/passats' },
  { name: 'Fazier', url: 'https://fazier.com/launches/passats.pro', label: 'Launched on' },
  { name: 'BuildHop', url: 'https://buildhop.io/discover/passats-ba021024-5631-41cc-bf99-de9205bf7741', label: 'Launched on' },
];

module.exports = { LAUNCHES };
