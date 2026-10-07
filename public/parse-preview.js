/**
 * The free parse preview.
 *
 * Served from public/ as an external file rather than inlined. The CSP has no
 * 'unsafe-inline' for scripts, so an inline block here would need its hash
 * threaded through scripts/sync-csp-hashes.js and would break the page silently
 * the first time someone edited the markup without re-running it. `script-src
 * 'self'` already covers this file, and there is nothing to keep in sync.
 */
(function () {
  'use strict';

  var MAX_BYTES = 5 * 1024 * 1024;
  var ACCEPTED = /\.(pdf|docx)$/i;

  var input = document.getElementById('fileInput');
  var zone = document.getElementById('dropZone');
  var status = document.getElementById('status');
  var result = document.getElementById('result');
  var output = document.getElementById('output');
  var stats = document.getElementById('stats');
  var flag = document.getElementById('hiddenFlag');
  var pagePane = document.getElementById('pagePane');
  var pageImage = document.getElementById('pageImage');
  var contactBox = document.getElementById('contact');
  var contactList = document.getElementById('contactList');

  // Copy for each status. "later" is still a pass, with a warning: the detail
  // survived, but nowhere near the name, which usually means it came from a
  // sidebar or footer the parser read last.
  var CONTACT = {
    email: {
      label: 'Email',
      found: ['ok', 'Found near the top.'],
      later: ['warn', 'Found, but only further down. It probably came from a sidebar or footer the parser read last.'],
      broken: ['bad', 'Came out broken. There is an @ in the text, but the address is split apart. Check it in the text below.'],
      missing: ['bad', 'Not found. If your resume has one, the parser lost it. A page header, a text box or an icon is the usual cause.'],
    },
    phone: {
      label: 'Phone',
      found: ['ok', 'Found near the top.'],
      later: ['warn', 'Found, but only further down. It probably came from a sidebar or footer the parser read last.'],
      missing: ['bad', 'Not found. If your resume has one, the parser lost it. Write it as plain text under your name.'],
    },
    linkedin: {
      label: 'LinkedIn',
      found: ['ok', 'Address found.'],
      later: ['ok', 'Address found.'],
      label_only: ['warn', 'The word is there but the address is not. A link set on a word does not survive; write the address out.'],
      missing: ['info', 'Not found. Optional, but worth including as a written-out address.'],
    },
  };
  var ICON = { ok: '\u2713', warn: '!', bad: '\u2715', info: '\u2013' };

  function showContact(contact) {
    contactList.textContent = '';
    if (!contact) { contactBox.hidden = true; return; }
    ['email', 'phone', 'linkedin'].forEach(function (key) {
      var spec = CONTACT[key];
      var finding = contact[key] || {};
      var status = finding.status === 'found' && finding.position === 'later' ? 'later' : finding.status;
      var copy = spec[status];
      if (!copy) return;
      var item = document.createElement('li');
      item.className = 'contact-item contact-' + copy[0];
      var title = document.createElement('strong');
      var icon = document.createElement('span');
      icon.className = 'contact-icon';
      icon.setAttribute('aria-hidden', 'true');
      icon.textContent = ICON[copy[0]];
      title.appendChild(icon);
      title.appendChild(document.createTextNode(spec.label));
      item.appendChild(title);
      item.appendChild(document.createTextNode(copy[1]));
      contactList.appendChild(item);
    });
    contactBox.hidden = !contactList.children.length;
  }
  var busy = false;

  function say(message, kind) {
    status.textContent = message || '';
    status.className = 'status' + (kind ? ' status-' + kind : '');
    status.hidden = !message;
  }

  function reset() {
    result.hidden = true;
    result.classList.remove('has-page');
    pagePane.hidden = true;
    pageImage.removeAttribute('src');
    showContact(null);
    flag.hidden = true;
    say('');
  }

  function describe(hidden) {
    var words = {
      invisible: 'set to render invisibly',
      white: 'set in white on a white page',
      tiny: 'set too small to read',
    };
    var how = (hidden.reasons || []).map(function (r) { return words[r]; })
      .filter(Boolean).join(', ');
    return hidden.chars + ' characters ' + (how || 'hidden from the page')
      + '. That text is excluded from the preview above, and from the score if you run a full analysis.';
  }

  async function send(file) {
    if (busy) return;
    reset();

    if (!ACCEPTED.test(file.name)) {
      say('Upload a PDF or DOCX. An ATS cannot read anything else either.', 'error');
      return;
    }
    if (file.size > MAX_BYTES) {
      say('That file is over 5 MB. Trim it and try again.', 'error');
      return;
    }

    busy = true;
    zone.setAttribute('aria-busy', 'true');
    say('Reading your file…');

    var body = new FormData();
    body.append('cv', file);

    try {
      var response = await fetch('/api/parse-preview', { method: 'POST', body: body });
      var data = await response.json().catch(function () { return {}; });
      if (!response.ok) {
        say(data.error || 'We could not read that file.', 'error');
        return;
      }

      // textContent, never innerHTML: this string came out of a file someone
      // else supplied and is rendered straight back onto the page.
      output.textContent = data.text;
      stats.textContent = data.chars.toLocaleString() + ' characters'
        + (data.truncated ? ' (showing the first 20,000)' : '')
        + ' · ' + file.name;
      // Only ever a PNG data URL that the server rendered. Anything else is
      // ignored and the text shows alone, which is also what happens for a
      // DOCX or when the render was skipped.
      var page = data.page;
      if (page && typeof page.image === 'string' && page.image.indexOf('data:image/png;base64,') === 0) {
        pageImage.width = page.width;
        pageImage.height = page.height;
        pageImage.src = page.image;
        pagePane.hidden = false;
        result.classList.add('has-page');
      }
      showContact(data.contact);
      if (data.hidden && data.hidden.flagged) {
        flag.textContent = describe(data.hidden);
        flag.hidden = false;
      }
      result.hidden = false;
      say('');
      result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (err) {
      say('Something went wrong reading that file. Try again.', 'error');
    } finally {
      busy = false;
      zone.removeAttribute('aria-busy');
    }
  }

  input.addEventListener('change', function () {
    if (input.files && input.files[0]) send(input.files[0]);
  });

  ['dragenter', 'dragover'].forEach(function (name) {
    zone.addEventListener(name, function (event) {
      event.preventDefault();
      zone.classList.add('is-over');
    });
  });
  ['dragleave', 'drop'].forEach(function (name) {
    zone.addEventListener(name, function (event) {
      event.preventDefault();
      zone.classList.remove('is-over');
    });
  });
  zone.addEventListener('drop', function (event) {
    var file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
    if (file) send(file);
  });
})();
