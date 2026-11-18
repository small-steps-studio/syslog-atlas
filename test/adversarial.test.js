'use strict';
// Hostile inputs (test/helpers/adversarial-input.js): text from a file must never become a link, an image, HTML or an extra
// table cell in a report, and no report may throw.
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('../src/core');
const { cases } = require('./helpers/adversarial-input');

const reports = Object.keys(core).filter((k) => /^report/.test(k));
// Unescaped means: not preceded by an odd number of backslashes.
const UNESC = (re) => new RegExp('(^|[^\\\\])(\\\\\\\\)*' + re);
// inline math of the built-in Markdown preview: $...$ where neither dollar is escaped
const MATH = /(^|[^\\])(\\\\)*\$[^\s$][^$\n]*?[^\\\s]\$/;
const IMAGE = UNESC('!\\['), LINK = UNESC('\\]\\('), TAG = UNESC('<\\/?[A-Za-z!]'), AUTOLINK = UNESC('<https?:');

// The text outside fenced code blocks: Markdown shows fenced content literally (no links, images, HTML or math), so the
// injection checks look only outside. CommonMark rule: a fence of n backticks is closed by a line of at least n backticks;
// a payload that closes a fence early leaves the rest outside, where it is checked.
function outsideFences(md) {
  const out = []; let fence = 0;
  for (const line of md.split('\n')) {
    const m = /^ {0,3}(`{3,})(.*)$/.exec(line);
    if (!fence) { if (m && !m[2].includes('`')) { fence = m[1].length; continue; } out.push(line); }
    else if (m && m[1].length >= fence && !m[2].trim()) fence = 0;
  }
  return out.join('\n');
}

function cells(row) { let n = 0, esc = false; for (const c of row) { if (esc) { esc = false; continue; } if (c === '\\') { esc = true; continue; } if (c === '|') n++; } return n; }

for (const c of cases) {
  test('adversarial: ' + c.name, () => {
    for (const r of reports) {
      let md;
      assert.doesNotThrow(() => { md = core[r](c.text); }, r + ' threw');
      assert.equal(typeof md, 'string');
      assert.ok(md.startsWith('# '), r + ': no heading');
      const text = outsideFences(md);
      assert.ok(!IMAGE.test(text), r + ': unescaped image in\n' + md);
      assert.ok(!LINK.test(text), r + ': unescaped link in\n' + md);
      assert.ok(!TAG.test(text), r + ': unescaped HTML tag in\n' + md);
      assert.ok(!AUTOLINK.test(text), r + ': unescaped autolink in\n' + md);
      assert.ok(!MATH.test(text), r + ': unescaped $...$ (math) in\n' + md);
      assert.ok(!/Infinity|NaN|undefined|\[object Object\]/.test(md), r + ': Infinity/NaN/undefined/[object Object] in\n' + md);
      // every table keeps the column count of its header row
      const lines = md.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (!lines[i].startsWith('|') || !/^\|[ :-]+\|/.test(lines[i + 1] || '')) continue;
        const want = cells(lines[i]);
        for (let k = i + 2; k < lines.length && lines[k].startsWith('|'); k++) assert.equal(cells(lines[k]), want, r + ': row ' + k + ' has another column count: ' + lines[k]);
      }
    }
  });
}
