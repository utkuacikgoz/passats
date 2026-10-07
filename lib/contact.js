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

const EMAIL = /[A-Z0-9._%+-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)*\.[A-Z]{2,}/i;
// An @ with a word on either side, allowing the stray spaces and line breaks a
// parser inserts when it splits an address across text runs.
const EMAIL_FRAGMENT = /[A-Z0-9._%+-]+\s*@\s*[A-Z0-9-]+(?:\s*\.\s*[A-Z0-9-]+)+/i;

// A run of digits and the separators phone numbers are written with. Checked
// for digit count afterwards, so the pattern itself can stay loose.
const PHONE_CANDIDATE = /\+?\(?\d[\d ().\- ]{5,}\d/g;
const YEAR = /^(?:19|20)\d{2}$/;

const LINKEDIN_URL = /linkedin\.com\/in\/[A-Z0-9_%-]+/i;
const LINKEDIN_WORD = /\blinked\s?in\b/i;

function position(index, length) {
  return index <= Math.max(TOP_CHARS, length * TOP_FRACTION) ? 'top' : 'later';
}

function isPhone(candidate) {
  const digits = candidate.replace(/\D/g, '');
  if (digits.length < 7 || digits.length > 15) return false;
  // Date ranges and runs of years are the commonest digit strings on a resume:
  // "2018-2021", "2016 2018 2020". If every group is a year, it is not a phone.
  const groups = candidate.split(/[^\d]+/).filter(Boolean);
  if (groups.every(group => YEAR.test(group))) return false;
  return true;
}

function findPhone(text) {
  for (const match of text.matchAll(PHONE_CANDIDATE)) {
    if (isPhone(match[0])) return match.index;
  }
  return -1;
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
  const source = typeof text === 'string' ? text : '';
  const length = source.length;
  const at = index => position(index, length);

  let email;
  const exact = source.search(EMAIL);
  if (exact !== -1) {
    email = { status: 'found', position: at(exact) };
  } else {
    const fragment = source.search(EMAIL_FRAGMENT);
    email = fragment !== -1 ? { status: 'broken', position: at(fragment) } : { status: 'missing' };
  }

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

module.exports = { checkContact, isPhone, TOP_CHARS };
