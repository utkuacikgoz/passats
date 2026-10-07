'use strict';

// The moving "featured on" band is generated from config/launches.js. These
// pin what a generator can quietly get wrong: drift from the config, repeats
// that a screen reader or the keyboard can reach, and motion that ignores the
// visitor's reduced-motion setting.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { sync, START, END } = require('../scripts/sync-launches');
const { LAUNCHES } = require('../config/launches');

const html = fs.readFileSync(path.join(__dirname, '..', 'views', 'index.html'), 'utf8');
const strip = page => page.slice(page.indexOf(START), page.indexOf(END));

describe('launch strip', () => {
  it('is current with config/launches.js', () => {
    assert.equal(sync(html), html, 'run npm run sync:launches');
  });

  it('exposes each launch exactly once to assistive tech and the keyboard', () => {
    const three = [
      { name: 'Alpha', url: 'https://alpha.test/passats' },
      { name: 'Beta', url: 'https://beta.test/passats', label: 'Launched on' },
      { name: 'Gamma', url: 'https://gamma.test/passats' },
    ];
    for (const launches of [LAUNCHES, three]) {
      const band = strip(sync(html, launches));
      const links = [...band.matchAll(/<li( aria-hidden="true")?><a [^>]*?(tabindex="-1")?>/g)];
      const reachable = links.filter(m => !m[1]);
      assert.equal(reachable.length, launches.length);
      for (const m of links.filter(m => m[1])) assert.ok(m[2], 'a hidden repeat must leave the tab order');
      // Two identical tracks, or the loop has a visible seam.
      const tracks = [...band.matchAll(/<ul class="marquee-track"[^>]*>([\s\S]*?)<\/ul>/g)];
      assert.equal(tracks.length, 2);
      const strip_ = s => s.replace(/ aria-hidden="true"| tabindex="-1"/g, '');
      assert.equal(strip_(tracks[0][1]), strip_(tracks[1][1]));
      assert.ok(links.length / 2 >= 6, 'each track overruns a wide screen');
    }
  });

  it('keeps sameAs in the Organization JSON-LD in step', () => {
    const next = sync(html, [...LAUNCHES, { name: 'Elsewhere', url: 'https://elsewhere.test/p' }]);
    const sameAs = JSON.parse(next.match(/"sameAs":\s*(\[[\s\S]*?\])/)[1]);
    assert.deepEqual(sameAs, [...LAUNCHES.map(l => l.url), 'https://elsewhere.test/p']);
  });

  it('refuses a bad config rather than shipping it', () => {
    assert.throws(() => sync(html, []));
    assert.throws(() => sync(html, [{ name: 'Plain', url: 'http://insecure.test/' }]));
    assert.throws(() => sync(html, [{ name: 'A', url: 'https://a.test/' }, { name: 'B', url: 'https://a.test/' }]));
    assert.throws(() => sync(html, [{ name: '', url: 'https://a.test/' }]));
  });

  it('escapes what goes into the markup', () => {
    const band = strip(sync(html, [{ name: '<script>x</script>', url: 'https://a.test/?a=1&b="2"' }]));
    assert.doesNotMatch(band, /<script>/);
    assert.match(band, /href="https:\/\/a\.test\/\?a=1&amp;b=&quot;2&quot;"/);
  });

  it('stands still for reduced motion and pauses for hover and focus', () => {
    assert.match(html, /@media \(prefers-reduced-motion: reduce\) \{\s*\.marquee \{[^}]*\}\s*\.marquee-reel \{ animation: none;/);
    assert.match(html, /\.launch-strip:focus-within \.marquee-reel \{ animation-play-state: paused; \}/);
  });
});

describe('launch strip edge cases', () => {
  it('writes a URL containing replacement tokens literally into sameAs', () => {
    const url = 'https://x.test/a$&b$1c';
    const next = sync(html, [{ name: 'Odd', url }]);
    const sameAs = JSON.parse(next.match(/"sameAs":\s*(\[[\s\S]*?\])/)[1]);
    assert.deepEqual(sameAs, [url]);
  });

  it('makes each track at least as wide as the screen', () => {
    assert.match(html, /\.marquee-track \{[^}]*min-width: 100vw;/);
  });
});
