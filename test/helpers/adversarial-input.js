'use strict';
// Hostile and odd log lines for the adversarial test (invented; payloads must come out as plain escaped text).
const PAY = ['x|y', '<b>y</b>', '[link](https://evil.test)', '<img src=https://evil.test/i.png>', '*b*', '_i_', '$x$', 'www.evil.test', '`code`'];
const cases = [];
PAY.forEach((p, i) => {
  const w = p.replace(/\s/g, '');
  cases.push({ name: 'payload ' + i, text: 'Nov 18 10:00:00 ' + w + ' ' + w + '[1]: Failed password for ' + w + ' from ' + w + ' port 1\n' + 'CEF:0|' + p + '|' + p + '|1|' + p + '|' + p + '|9|src=' + w + ' suser=' + w + '\n' + p + '\n' });
});
cases.push({ name: 'prototype names', text: 'Nov 18 10:00:00 __proto__ constructor[1]: Failed password for toString from hasOwnProperty port 1\nCEF:0|__proto__|constructor|1|valueOf|toString|9|src=__proto__\n' });
cases.push({ name: 'huge line', text: 'Nov 18 10:00:00 h p: ' + 'a'.repeat(300000) + '\n' + '<'.repeat(100000) });
cases.push({ name: 'many pipes', text: 'CEF:' + '|'.repeat(50000) + '\n' + 'CEF:0' + '\|'.repeat(20000) });
cases.push({ name: 'sd blocks', text: '<13>1 2026-01-01T00:00:00Z h a p m ' + '[x a="b"]'.repeat(10000) + ' msg\n' });
module.exports = { cases };
