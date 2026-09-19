# Vendored fonts

## DMSerifDisplay-Regular.ttf

The wordmark face. Vendored so `scripts/build-logo.js` is reproducible offline
and the logo cannot change shape when Google reissues the file.

- Source: https://fonts.google.com/specimen/DM+Serif+Display
- Licence: SIL Open Font License 1.1 — full text in `OFL.txt`

The OFL permits redistribution of the font file provided the licence travels
with it, which is why `OFL.txt` sits beside it. The site itself does not serve
this file: pages load the face from Google Fonts at runtime, and this copy exists
only so the build can convert glyphs to paths.
