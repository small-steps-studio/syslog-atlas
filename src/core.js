'use strict';
// Syslog Atlas core: RFC 5424, BSD syslog and CEF line reading, parse check, severities, sources and security events.

const esc = (s) => String(s).replace(/[\r\n]+/g, ' ').replace(/([\\`*_{}\[\]()#+!|<>~&$])/g, '\\$1')
  .split('://').join('\\:\\/\\/').replace(/(^|[^A-Za-z0-9])www\./gi, (m, pre) => pre + m.slice(pre.length, pre.length + 3) + '\\.');
const cell = (s) => { s = String(s == null ? '' : s); return s === '' ? '-' : esc(s); };
const pl = (n, w) => n + ' ' + w + (n === 1 ? '' : 's');
const byText = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const SEVERITIES = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'informational', 'debug'];
const FACILITIES = ['kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock',
  'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'];
const MONTHS = 'Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec';

// CEF header: 'CEF:<version>|vendor|product|version|signature id|name|severity|extension' ('\|' and '\\' escape in the header).
function parseCef(s) {
  const i = s.indexOf('CEF:'); if (i < 0) return null;
  const rest = s.slice(i + 4); const parts = []; let cur = '';
  for (let k = 0; k < rest.length; k++) {
    const c = rest[k];
    if (c === '\\' && k + 1 < rest.length && (rest[k + 1] === '|' || rest[k + 1] === '\\')) { cur += rest[k + 1]; k++; continue; }
    if (c === '|' && parts.length < 7) { parts.push(cur); cur = ''; continue; }
    cur += c;
  }
  parts.push(cur);
  if (parts.length < 8) return { ok: false, fields: parts.length };
  const [version, vendor, product, devVersion, signature, name, severity, extension] = parts;
  return { ok: true, version, vendor, product, devVersion, signature, name, severity: severity.trim(), extension };
}
// CEF severity: 0-3 Low, 4-6 Medium, 7-8 High, 9-10 Very-High; words Low, Medium, High, Very-High also allowed.
function cefLevel(sev) {
  const s = String(sev).trim();
  if (/^\d+$/.test(s)) { const n = +s; if (n > 10) return ''; return n <= 3 ? 'Low' : n <= 6 ? 'Medium' : n <= 8 ? 'High' : 'Very-High'; }
  const w = { low: 'Low', medium: 'Medium', high: 'High', 'very-high': 'Very-High' }[s.toLowerCase()];
  return w || '';
}

// One log line -> {format, pri, facility, severity, timestamp, host, program, message, cef, problem}
function parseLine(line) {
  const s = String(line == null ? '' : line);
  const out = { format: '', pri: null, facility: '', severity: '', timestamp: '', host: '', program: '', message: '', cef: null, problem: '' };
  let rest = s, m;
  if ((m = /^<(\d{1,3})>/.exec(rest))) {
    const pri = +m[1];
    if (pri > 191) { out.problem = 'PRI ' + pri + ' is above 191'; out.format = 'unknown'; return out; }
    out.pri = pri; out.facility = FACILITIES[pri >> 3]; out.severity = SEVERITIES[pri & 7]; rest = rest.slice(m[0].length);
  }
  if ((m = /^(\d{1,2}) (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (.*))?$/.exec(rest)) && out.pri !== null) {
    out.format = 'RFC 5424'; out.timestamp = m[2] === '-' ? '' : m[2]; out.host = m[3] === '-' ? '' : m[3]; out.program = m[4] === '-' ? '' : m[4]; out.message = (m[8] || '').replace(/^\uFEFF/, '');
  } else if ((m = new RegExp('^((?:' + MONTHS + ') [ \\d]\\d \\d{2}:\\d{2}:\\d{2}|\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:\\d{2})) (\\S+) (.*)$').exec(rest))) {
    out.format = 'BSD'; out.timestamp = m[1];
    if (m[2].startsWith('CEF:')) out.message = m[2] + ' ' + m[3];          // 'timestamp CEF:...' (no host name)
    else {
      out.host = m[2];
      const t = /^([^\s:\[]+)(?:\[(\d+)\])?: ?(.*)$/.exec(m[3]);
      if (t) { out.program = t[1]; out.message = t[3]; } else out.message = m[3];
    }
  } else if (/CEF:/.test(rest)) {
    out.format = 'CEF';
  } else { out.format = 'unknown'; out.problem = out.pri !== null ? 'the text after the PRI is neither RFC 5424 nor BSD syslog' : 'the line matches no syslog or CEF format'; return out; }
  const cefAt = (out.message || rest).indexOf('CEF:');
  if (cefAt >= 0) {
    const c = parseCef((out.message || rest).slice(cefAt));
    if (!c.ok) { out.problem = 'the CEF header has ' + c.fields + ' of 8 fields'; out.format = 'CEF'; return out; }
    out.format = 'CEF'; out.cef = c;
    if (!cefLevel(c.severity)) out.problem = 'CEF severity ' + c.severity + ' is not 0 to 10 or Low, Medium, High, Very-High';
  }
  return out;
}

function load(text) {
  return String(text == null ? '' : text).replace(/^\uFEFF/, '').split('\n').map((l, i) => ({ n: i + 1, t: l.replace(/\r$/, '') })).filter((x) => x.t.trim()).map((x) => Object.assign(x, { p: parseLine(x.t) }));
}
const NONE = (h) => '# ' + h + '\n\nThe file contains no log lines.';
const count = (map, k) => map.set(k, (map.get(k) || 0) + 1);
const top = (map, n) => [...map.entries()].sort((a, b) => b[1] - a[1] || byText(a[0], b[0])).slice(0, n);

function reportSummary(text) {
  const L = load(text); const H = 'Log Summary'; if (!L.length) return NONE(H);
  const fm = new Map(), hosts = new Set(), progs = new Map();
  L.forEach((x) => { count(fm, x.p.format); if (x.p.host) hosts.add(x.p.host); if (x.p.program) count(progs, x.p.program); });
  const ts = L.filter((x) => x.p.timestamp);
  let md = '# ' + H + '\n\n' + pl(L.length, 'line') + ' from ' + pl(hosts.size, 'host') + '.';
  md += '\n\n| Format | Lines |\n| --- | ---: |\n' + ['RFC 5424', 'BSD', 'CEF', 'unknown'].filter((f) => fm.has(f)).map((f) => '| ' + f + ' | ' + fm.get(f) + ' |').join('\n');
  md += '\n\n' + (ts.length ? 'First entry: ' + cell(ts[0].p.timestamp) + ' (line ' + ts[0].n + '). Last entry: ' + cell(ts[ts.length - 1].p.timestamp) + ' (line ' + ts[ts.length - 1].n + ').' : 'No timestamps.');
  md += '\n\n' + (progs.size ? '| Program | Lines |\n| --- | ---: |\n' + top(progs, 10).map(([k, v]) => '| ' + cell(k) + ' | ' + v + ' |').join('\n') : 'No program names.');
  return md;
}

function reportParse(text) {
  const L = load(text); const H = 'Parse Check'; if (!L.length) return NONE(H);
  const bad = L.filter((x) => x.p.problem);
  if (!bad.length) return '# ' + H + '\n\nAll ' + pl(L.length, 'line') + ' parsed.';
  return '# ' + H + '\n\n' + bad.length + ' of ' + pl(L.length, 'line') + ' with problems.\n\n| Line | Problem | Text |\n| ---: | --- | --- |\n' +
    bad.map((x) => '| ' + x.n + ' | ' + cell(x.p.problem) + ' | ' + cell(x.t.length > 80 ? x.t.slice(0, 80) + '...' : x.t) + ' |').join('\n');
}

function reportSeverity(text) {
  const L = load(text); const H = 'Severity Overview'; if (!L.length) return NONE(H);
  const sev = new Map(), fac = new Map(), cefm = new Map();
  L.forEach((x) => { if (x.p.severity) count(sev, x.p.severity); if (x.p.facility) count(fac, x.p.facility); if (x.p.cef) { const lv = cefLevel(x.p.cef.severity); if (lv) count(cefm, lv); } });
  let md = '# ' + H;
  md += '\n\n## Syslog severity\n\n' + (sev.size ? '| Severity | Lines |\n| --- | ---: |\n' + SEVERITIES.filter((s) => sev.has(s)).map((s) => '| ' + s + ' | ' + sev.get(s) + ' |').join('\n') : 'No line carries a PRI value.');
  md += '\n\n## Facility\n\n' + (fac.size ? '| Facility | Lines |\n| --- | ---: |\n' + FACILITIES.filter((s) => fac.has(s)).map((s) => '| ' + s + ' | ' + fac.get(s) + ' |').join('\n') : 'No line carries a PRI value.');
  md += '\n\n## CEF severity\n\n' + (cefm.size ? '| Severity | Events |\n| --- | ---: |\n' + ['Low', 'Medium', 'High', 'Very-High'].filter((s) => cefm.has(s)).map((s) => '| ' + s + ' | ' + cefm.get(s) + ' |').join('\n') : 'No CEF events.');
  return md;
}

function reportSources(text) {
  const L = load(text); const H = 'Sources'; if (!L.length) return NONE(H);
  const hp = new Map();
  L.forEach((x) => { if (!x.p.host && !x.p.program) return; const k = (x.p.host || '-') + '\u0000' + (x.p.program || '-'); if (!hp.has(k)) hp.set(k, { n: 0, err: 0 }); const e = hp.get(k); e.n++;
    if (x.p.pri !== null && (x.p.pri & 7) <= 3) e.err++; });
  const dev = new Map(), sig = new Map();
  L.forEach((x) => { if (!x.p.cef) return; count(dev, x.p.cef.vendor + '\u0000' + x.p.cef.product); count(sig, x.p.cef.signature + '\u0000' + x.p.cef.name); });
  let md = '# ' + H + '\n\n## Hosts and programs\n\n' + (hp.size ? '| Host | Program | Lines | Errors or worse |\n| --- | --- | ---: | ---: |\n' +
    [...hp.entries()].sort((a, b) => b[1].n - a[1].n || byText(a[0], b[0])).map(([k, e]) => { const [h, p] = k.split('\u0000'); return '| ' + cell(h === '-' ? '' : h) + ' | ' + cell(p === '-' ? '' : p) + ' | ' + e.n + ' | ' + e.err + ' |'; }).join('\n') : 'No host or program names.');
  md += '\n\n## CEF devices\n\n' + (dev.size ? '| Vendor | Product | Events |\n| --- | --- | ---: |\n' + top(dev, 1e9).map(([k, v]) => { const [a, b] = k.split('\u0000'); return '| ' + cell(a) + ' | ' + cell(b) + ' | ' + v + ' |'; }).join('\n') : 'No CEF events.');
  if (sig.size) md += '\n\n## Top CEF signatures\n\n| Signature | Name | Events |\n| --- | --- | ---: |\n' + top(sig, 20).map(([k, v]) => { const [a, b] = k.split('\u0000'); return '| ' + cell(a) + ' | ' + cell(b) + ' | ' + v + ' |'; }).join('\n');
  return md;
}

// Security events found in message text (sshd, sudo, su) and CEF events with severity 7 or more.
function securityEvent(p) {
  const msg = p.message || ''; let m;
  if ((m = /Failed (?:password|publickey|keyboard-interactive\/pam) for (invalid user )?(\S+) from (\S+)/.exec(msg))) return { kind: m[1] ? 'failed login (invalid user)' : 'failed login', user: m[2], ip: m[3] };
  if ((m = /Invalid user (\S+) from (\S+)/.exec(msg))) return { kind: 'invalid user', user: m[1], ip: m[2] };
  if ((m = /Accepted (?:password|publickey|keyboard-interactive\/pam) for (\S+) from (\S+)/.exec(msg))) return { kind: 'accepted login', user: m[1], ip: m[2] };
  if (p.program === 'sudo' && (m = /^\s*(\S+) : .*COMMAND=(.*)$/.exec(msg))) return { kind: 'sudo', user: m[1], ip: '' };
  if ((m = /authentication failure;.*?(?:rhost=(\S*))?.*?user=(\S+)/.exec(msg))) return { kind: 'authentication failure', user: m[2], ip: m[1] || '' };
  if (p.program === 'su' && /fail/i.test(msg)) { const u = /\bfor (\S+)/.exec(msg); return { kind: 'su failure', user: u ? u[1] : '', ip: '' }; }
  if (p.cef) { const n = /^\d+$/.test(p.cef.severity) ? +p.cef.severity : { high: 7, 'very-high': 9 }[p.cef.severity.toLowerCase()] || 0;
    if (n >= 7) { const src = /(?:^|\s)src=(\S+)/.exec(p.cef.extension); const usr = /(?:^|\s)suser=(\S+)/.exec(p.cef.extension); return { kind: 'CEF ' + cefLevel(p.cef.severity) + ': ' + p.cef.name, user: usr ? usr[1] : '', ip: src ? src[1] : '' }; } }
  return null;
}
function reportSecurity(text) {
  const L = load(text); const H = 'Security Events'; if (!L.length) return NONE(H);
  const ev = []; L.forEach((x) => { const e = securityEvent(x.p); if (e) ev.push(Object.assign({ n: x.n, ts: x.p.timestamp }, e)); });
  if (!ev.length) return '# ' + H + '\n\nNo security events found.';
  const kinds = new Map(); ev.forEach((e) => count(kinds, e.kind));
  const failIp = new Map(); ev.filter((e) => /^failed login|^invalid user|^authentication failure/.test(e.kind) && e.ip).forEach((e) => count(failIp, e.ip));
  const brute = top(failIp, 1e9).filter(([, v]) => v >= 5);
  let md = '# ' + H + '\n\n' + pl(ev.length, 'event') + '.\n\n| Event | Count |\n| --- | ---: |\n' + top(kinds, 1e9).map(([k, v]) => '| ' + cell(k) + ' | ' + v + ' |').join('\n');
  md += '\n\n## Possible brute force\n\n' + (brute.length ? '| Source | Failed attempts |\n| --- | ---: |\n' + brute.map(([k, v]) => '| ' + cell(k) + ' | ' + v + ' |').join('\n') : 'No source with 5 or more failed attempts.');
  md += '\n\n## Events\n\n| Line | Time | Event | User | Source |\n| ---: | --- | --- | --- | --- |\n' + ev.map((e) => '| ' + e.n + ' | ' + cell(e.ts) + ' | ' + cell(e.kind) + ' | ' + cell(e.user) + ' | ' + cell(e.ip) + ' |').join('\n');
  return md;
}

module.exports = { parseLine, cefLevel, reportSummary, reportParse, reportSeverity, reportSources, reportSecurity };

// Caps every Markdown table of a report at 500 rows and says how many there were.
function capTables(md) {
  if (typeof md !== 'string') return md;
  const lines = md.split('\n'), out = [];
  for (let i = 0; i < lines.length; i++) {
    out.push(lines[i]);
    if (lines[i].startsWith('|') && /^\|[ :-]+\|/.test(lines[i + 1] || '')) {
      out.push(lines[++i]);
      let n = 0;
      while (i + 1 < lines.length && lines[i + 1].startsWith('|')) { i++; n++; if (n <= 500) out.push(lines[i]); }
      if (n > 500) { out.push(''); out.push('Showing the first 500 of ' + n + ' rows.'); }
    }
  }
  return out.join('\n');
}
for (const k of Object.keys(module.exports)) {
  if (k.startsWith('report')) { const f = module.exports[k]; module.exports[k] = function (text) { return capTables(f(text)); }; }
}
