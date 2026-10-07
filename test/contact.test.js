'use strict';

// The free contact check. A false "missing" sends someone to rebuild a resume
// that was fine, so the phone cases below lean towards the formats people
// actually type, and the negatives are the digit strings every resume has.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { checkContact, isPhone } = require('../lib/contact');

const BODY = 'EXPERIENCE\nSenior Data Analyst, Revolut 2021-2024\nBuilt the weekly retention dashboard used by 40 product managers.\n'.repeat(8);

describe('phone numbers', () => {
  for (const phone of [
    '+44 7700 900100', '(415) 555-0132', '415.555.0132', '+1 415 555 0132', '555 0100',
    '+90 532 123 45 67', '07700900100', '+49 (0)30 1234567',
  ]) {
    it(`counts ${phone}`, () => assert.equal(isPhone(phone), true));
  }
  for (const notPhone of ['2021-2024', '2016 2018 2020', '2019 - 2022', '1999', '40', '12 34']) {
    it(`does not count ${notPhone}`, () => assert.equal(isPhone(notPhone), false));
  }
  it('is not fooled by a resume that is all date ranges', () => {
    assert.equal(checkContact(`Dani Okonkwo\n${BODY}`).phone.status, 'missing');
  });
});

describe('checkContact', () => {
  it('finds all three under the name', () => {
    const out = checkContact(`Dani Okonkwo\ndani@example.com · +44 7700 900100 · linkedin.com/in/dani-okonkwo\n${BODY}`);
    assert.deepEqual(out, {
      email: { status: 'found', position: 'top' },
      phone: { status: 'found', position: 'top' },
      linkedin: { status: 'found', position: 'top' },
    });
  });

  it('says when the details only came out at the end', () => {
    // A sidebar or footer read last: present, but nowhere near the name.
    const out = checkContact(`Dani Okonkwo\n${BODY}dani@example.com +44 7700 900100`);
    assert.equal(out.email.position, 'later');
    assert.equal(out.phone.position, 'later');
  });

  it('reports everything missing when the header was dropped', () => {
    const out = checkContact(`Dani Okonkwo\n${BODY}`);
    assert.equal(out.email.status, 'missing');
    assert.equal(out.phone.status, 'missing');
    assert.equal(out.linkedin.status, 'missing');
  });

  it('tells a broken address from a missing one', () => {
    assert.equal(checkContact('dani @ example . com\n' + BODY).email.status, 'broken');
    assert.equal(checkContact('dani@example.\ncom\n' + BODY).email.status, 'broken');
  });

  it('notices LinkedIn as a word whose link did not survive', () => {
    assert.equal(checkContact('Dani Okonkwo · LinkedIn · GitHub\n' + BODY).linkedin.status, 'label_only');
  });

  it('never returns the values themselves', () => {
    const out = JSON.stringify(checkContact('dani@example.com +44 7700 900100 linkedin.com/in/dani'));
    assert.doesNotMatch(out, /dani|7700|example/);
  });

  it('survives input that is not a string', () => {
    for (const value of [undefined, null, 42, {}]) {
      assert.equal(checkContact(value).email.status, 'missing');
    }
  });
});

describe('untrusted input', () => {
  // These run synchronously on an anonymous upload. Each of these shapes made a
  // regex-based version backtrack; a linear walk handles all of them at once.
  const budget = 200;
  for (const [label, text] of [
    ['an @ followed by a long dotted run', 'a@' + 'a.'.repeat(100_000)],
    ['thousands of @ signs', '@'.repeat(150_000)],
    ['a long run of digits and spaces', '1 '.repeat(100_000)],
    ['a long run of date fragments', '2019 - '.repeat(30_000)],
  ]) {
    it(`stays linear on ${label}`, () => {
      const started = Date.now();
      checkContact(text);
      assert.ok(Date.now() - started < budget, `took ${Date.now() - started}ms`);
    });
  }

  it('does not let a date range and the next number pass as a phone', () => {
    // A DOCX flattens paragraphs to single spaces: a role ending "2019 - 2024"
    // followed by a bullet starting "100 customers" used to read as a phone.
    assert.equal(isPhone('2019 - 2024 100'), false);
    assert.equal(checkContact('Account Manager 2019 - 2024 100 customers onboarded').phone.status, 'missing');
    assert.equal(checkContact('Analyst 2019–present 120 dashboards shipped').phone.status, 'missing');
  });

  it('still finds a phone that runs into the next number', () => {
    assert.equal(checkContact('+44 7700 900100 40 product managers').phone.status, 'found');
  });
});
