/**
 * Did your contact details survive extraction?
 *
 * The most expensive parsing failure is also the quietest: a resume whose email
 * or phone number lives in a page header, a text box or an icon comes out of
 * the parser without them. The candidate is unreachable and nothing tells them.
 * This reads the extracted text, the same text the analysis scores, and says
 * which details made it through and where they landed.
 *
 * It reports, it never repairs, and it never echoes a value back: the visitor
 * already knows their own email, and the free preview should not become a way
 * to harvest one from someone else's file.
 *
 * The rule from lib/hidden-text.js applies here in reverse. A false "missing"
 * sends someone to rebuild a resume that was fine, so detection is generous:
 * anything that plausibly is a phone number counts as one. The cost of that is
 * the occasional false "found", which leaves the visitor where they were.
 */
'use strict';

// Where a detail counts as "near the top". Contact details belong under the
// name; one that only appears late in the text usually came from a sidebar or
// a footer that the parser read last.
const TOP_CHARS = 400;
const TOP_FRACTION = 0.2;

// Everything here runs over text from an anonymous upload, synchronously, after
// the parser's own timeout has finished. So nothing scans that text with an
// open-ended pattern: a regex like /x+@y+(\.z+)*\.tld/ backtracks
// quadratically on "a@a.a.a..." and one crafted file would stall the process
// for every other visitor. Instead each check finds its anchors with a linear
// walk and only ever runs a pattern over a short, bounded slice.
//
// Contact details belong at the top, so there is nothing to find past this.
const MAX_SCAN_CHARS = 200_000;
// Bounded work per anchor, and a bounded number of anchors.
const MAX_AT_SIGNS = 200;
const LOCAL_MAX = 64;
const DOMAIN_MAX = 255;
const BROKEN_WINDOW = 80;

const EMAIL_EXACT = /^[A-Z0-9._%+-]{1,64}@[A-Z0-9-]{1,63}(?:\.[A-Z0-9-]{1,63}){0,8}\.[A-Z]{2,24}$/i;
const LOCAL_CHAR = /[A-Z0-9._%+-]/i;
const DOMAIN_CHAR = /[A-Z0-9.-]/i;

const LINKEDIN_URL = /linkedin\.com\/in\/[A-Z0-9_%-]/i;
const LINKEDIN_WORD = /\blinked ?in\b/i;

// Date ranges are the commonest digit strings on a resume. They are masked
// before phone numbers are looked for, so "2019 - 2024" cannot combine with
// the number that starts the next line into something phone-shaped. Every
// quantifier is bounded, so this is linear.
const DATE_RANGE = /\b(?:19|20)\d{2}[ \u00a0]{0,3}[-\u2013\u2014][ \u00a0]{0,3}(?:(?:19|20)\d{2}|present|current|now|today)\b/gi;
const PHONE_START = /[\d+(]/;
const PHONE_CHAR = /[\d ().+\-\u00a0]/;
const YEAR = /^(?:19|20)\d{2}$/;
const MAX_PHONE_GROUPS = 12;

function position(index, length) {
  return index <= Math.max(TOP_CHARS, length * TOP_FRACTION) ? 'top' : 'later';
}

/** Is this run of digits and separators a phone number? */
function isPhone(candidate) {
  const groups = String(candidate).replace(DATE_RANGE, '|').split(/\D+/).filter(Boolean).slice(0, MAX_PHONE_GROUPS);
  // A number written as several groups can run into whatever digits follow it
  // once a document is flattened to text. Take the longest leading set of
  // groups that is phone-length, rather than rejecting the whole run.
  let digits = 0;
  let best = 0;
  for (let i = 0; i < groups.length; i++) {
    digits += groups[i].length;
    if (digits > 15) break;
    if (digits >= 7) best = i + 1;
  }
  if (!best) return false;
  // "2016 2018 2020": runs of years are not a phone.
  return !groups.slice(0, best).every(group => YEAR.test(group));
}

function findPhone(text) {
  const masked = text.replace(DATE_RANGE, match => '|'.repeat(match.length));
  let i = 0;
  while (i < masked.length) {
    if (!PHONE_START.test(masked[i])) { i++; continue; }
    let j = i + 1;
    while (j < masked.length && PHONE_CHAR.test(masked[j])) j++;
    if (isPhone(masked.slice(i, j))) return i;
    i = j;
  }
  return -1;
}

/** The address around one @, read outwards from it with a bound each way. */
function addressAt(text, at) {
  let left = at;
  while (left > 0 && at - left < LOCAL_MAX && LOCAL_CHAR.test(text[left - 1])) left--;
  let right = at + 1;
  while (right < text.length && right - at <= DOMAIN_MAX && DOMAIN_CHAR.test(text[right])) right++;
  const candidate = text.slice(left, right).replace(/[.-]+$/, '');
  return { start: left, valid: left < at && EMAIL_EXACT.test(candidate) };
}

function findEmail(text) {
  let firstBroken = -1;
  let at = text.indexOf('@');
  for (let seen = 0; at !== -1 && seen < MAX_AT_SIGNS; seen++, at = text.indexOf('@', at + 1)) {
    const exact = addressAt(text, at);
    if (exact.valid) return { status: 'found', index: exact.start };
    if (firstBroken === -1) {
      // The same address with the whitespace a parser inserts taken out:
      // "dani @ example . com" or a domain split across two lines.
      const from = Math.max(0, at - BROKEN_WINDOW);
      // Only the whitespace around the @ and the dots goes: anything else still
      // ends the address, so it cannot run on into the next line's words.
      const before = text.slice(from, at).replace(/\s+$/, '');
      const after = text.slice(at + 1, at + 1 + BROKEN_WINDOW).replace(/^\s+/, '').replace(/\s*\.\s*/g, '.');
      const joined = `${before}@${after}`;
      if (addressAt(joined, before.length).valid) firstBroken = at;
    }
  }
  return firstBroken !== -1 ? { status: 'broken', index: firstBroken } : { status: 'missing' };
}

/**
 * @param {string} text extracted resume text, after hidden text was removed
 * @returns {{
 *   email:    { status: 'found' | 'broken' | 'missing', position?: 'top' | 'later' },
 *   phone:    { status: 'found' | 'missing', position?: 'top' | 'later' },
 *   linkedin: { status: 'found' | 'label_only' | 'missing', position?: 'top' | 'later' },
 * }}
 */
function checkContact(text) {
  const source = (typeof text === 'string' ? text : '').slice(0, MAX_SCAN_CHARS);
  const length = source.length;
  const at = index => position(index, length);

  const foundEmail = findEmail(source);
  const email = foundEmail.status === 'missing'
    ? { status: 'missing' }
    : { status: foundEmail.status, position: at(foundEmail.index) };

  const phoneAt = findPhone(source);
  const phone = phoneAt !== -1 ? { status: 'found', position: at(phoneAt) } : { status: 'missing' };

  let linkedin;
  const url = source.search(LINKEDIN_URL);
  if (url !== -1) {
    linkedin = { status: 'found', position: at(url) };
  } else {
    // The word without the address: a hyperlink set on the word "LinkedIn", or
    // an icon with a label. The link target is not text, so it did not survive.
    const word = source.search(LINKEDIN_WORD);
    linkedin = word !== -1 ? { status: 'label_only', position: at(word) } : { status: 'missing' };
  }

  return { email, phone, linkedin };
}

module.exports = { checkContact, isPhone, TOP_CHARS, MAX_SCAN_CHARS };
