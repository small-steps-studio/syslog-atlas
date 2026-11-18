'use strict';
// Contract tests: written from the specification examples. Do not edit; fix src/core.js instead.
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('../src/core');

const plain = (v) => JSON.parse(JSON.stringify(v === undefined ? null : v));

test('core exports every specified function', () => {
  for (const n of ["parseLine", "cefLevel", "reportSummary", "reportParse", "reportSeverity", "reportSources", "reportSecurity"]) assert.equal(typeof core[n], 'function', n);
});

test("parseLine example 1", () => {
  assert.deepStrictEqual(plain(core.parseLine("<34>1 2026-11-18T09:20:00.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8")), {"format": "RFC 5424", "pri": 34, "facility": "auth", "severity": "critical", "timestamp": "2026-11-18T09:20:00.003Z", "host": "mymachine.example.com", "program": "su", "message": "'su root' failed for lonvick on /dev/pts/8", "cef": null, "problem": ""});
});

test("parseLine example 2", () => {
  assert.deepStrictEqual(plain(core.parseLine("Nov 18 09:12:01 web1 sshd[2210]: Failed password for root from 203.0.113.7 port 52211 ssh2")), {"format": "BSD", "pri": null, "facility": "", "severity": "", "timestamp": "Nov 18 09:12:01", "host": "web1", "program": "sshd", "message": "Failed password for root from 203.0.113.7 port 52211 ssh2", "cef": null, "problem": ""});
});

test("parseLine example 3", () => {
  assert.deepStrictEqual(plain(core.parseLine("Sep 18 12:00:00 CEF:0|Example Security|Edge FW|1.2|4001|Port scan detected|8|src=203.0.113.9")), {"format": "CEF", "pri": null, "facility": "", "severity": "", "timestamp": "Sep 18 12:00:00", "host": "", "program": "", "message": "CEF:0|Example Security|Edge FW|1.2|4001|Port scan detected|8|src=203.0.113.9", "cef": {"ok": true, "version": "0", "vendor": "Example Security", "product": "Edge FW", "devVersion": "1.2", "signature": "4001", "name": "Port scan detected", "severity": "8", "extension": "src=203.0.113.9"}, "problem": ""});
});

test("parseLine example 4", () => {
  assert.deepStrictEqual(plain(core.parseLine("<999>bad pri")), {"format": "unknown", "pri": null, "facility": "", "severity": "", "timestamp": "", "host": "", "program": "", "message": "", "cef": null, "problem": "PRI 999 is above 191"});
});

test("parseLine example 5", () => {
  assert.deepStrictEqual(plain(core.parseLine("CEF:0|Broken|Header|1.0|x")), {"format": "CEF", "pri": null, "facility": "", "severity": "", "timestamp": "", "host": "", "program": "", "message": "", "cef": null, "problem": "the CEF header has 5 of 8 fields"});
});

test("parseLine example 6", () => {
  assert.deepStrictEqual(plain(core.parseLine("plain text")), {"format": "unknown", "pri": null, "facility": "", "severity": "", "timestamp": "", "host": "", "program": "", "message": "", "cef": null, "problem": "the line matches no syslog or CEF format"});
});

test("cefLevel example 1", () => {
  assert.deepStrictEqual(plain(core.cefLevel("2")), "Low");
});

test("cefLevel example 2", () => {
  assert.deepStrictEqual(plain(core.cefLevel("8")), "High");
});

test("cefLevel example 3", () => {
  assert.deepStrictEqual(plain(core.cefLevel("10")), "Very-High");
});

test("cefLevel example 4", () => {
  assert.deepStrictEqual(plain(core.cefLevel("11")), "");
});

test("cefLevel example 5", () => {
  assert.deepStrictEqual(plain(core.cefLevel("very-high")), "Very-High");
});

test("cefLevel example 6", () => {
  assert.deepStrictEqual(plain(core.cefLevel("x")), "");
});

test("reportSummary example 1", () => {
  const md = core.reportSummary("Nov 18 09:12:01 web1 sshd[2210]: Failed password for invalid user admin from 203.0.113.7 port 52211 ssh2\nNov 18 09:12:03 web1 sshd[2210]: Failed password for invalid user admin from 203.0.113.7 port 52213 ssh2\nNov 18 09:12:05 web1 sshd[2212]: Failed password for root from 203.0.113.7 port 52215 ssh2\nNov 18 09:12:07 web1 sshd[2214]: Failed password for root from 203.0.113.7 port 52217 ssh2\nNov 18 09:12:09 web1 sshd[2216]: Failed password for root from 203.0.113.7 port 52219 ssh2\nNov 18 09:15:22 web1 sshd[2301]: Accepted publickey for deploy from 198.51.100.4 port 40022 ssh2: ED25519 SHA256:abc\nNov 18 09:16:00 web1 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx\nNov  8 10:00:00 web1 CRON[3000]: (root) CMD (run-parts /etc/cron.hourly)\n<34>1 2026-11-18T09:20:00.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8\n<165>1 2026-11-18T09:21:00Z db1 postgres 4211 - [meta sequenceId=\"1\"] connection received\n<11>Nov 18 09:22:00 fw1 kernel: segfault at 0\n<999>bad pri\nSep 18 12:00:00 CEF:0|Example Security|Edge FW|1.2|4001|Port scan detected|8|src=203.0.113.9 dst=10.0.0.5 suser=alice\nCEF:0|Example Security|Edge FW|1.2|1002|Allowed connection|2|src=10.0.0.8\nCEF:0|Broken|Header|1.0|x\nthis is not a log line\n");
  assert.equal(typeof md, 'string');
  for (const s of ["16 lines from 4 hosts.", "| Format | Lines |", "| RFC 5424 | 2 |", "| BSD | 9 |", "| CEF | 3 |", "| unknown | 2 |", "First entry: Nov 18 09:12:01 (line 1). Last entry: Sep 18 12:00:00 (line 13).", "| Program | Lines |", "| sshd | 6 |", "| CRON | 1 |", "| kernel | 1 |", "| postgres | 1 |", "| su | 1 |", "| sudo | 1 |"]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportSummary example 2", () => {
  const md = core.reportSummary("\n\n");
  assert.equal(typeof md, 'string');
  for (const s of ["# Log Summary", "The file contains no log lines."]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportParse example 1", () => {
  const md = core.reportParse("Nov 18 09:12:01 web1 sshd[2210]: Failed password for invalid user admin from 203.0.113.7 port 52211 ssh2\nNov 18 09:12:03 web1 sshd[2210]: Failed password for invalid user admin from 203.0.113.7 port 52213 ssh2\nNov 18 09:12:05 web1 sshd[2212]: Failed password for root from 203.0.113.7 port 52215 ssh2\nNov 18 09:12:07 web1 sshd[2214]: Failed password for root from 203.0.113.7 port 52217 ssh2\nNov 18 09:12:09 web1 sshd[2216]: Failed password for root from 203.0.113.7 port 52219 ssh2\nNov 18 09:15:22 web1 sshd[2301]: Accepted publickey for deploy from 198.51.100.4 port 40022 ssh2: ED25519 SHA256:abc\nNov 18 09:16:00 web1 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx\nNov  8 10:00:00 web1 CRON[3000]: (root) CMD (run-parts /etc/cron.hourly)\n<34>1 2026-11-18T09:20:00.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8\n<165>1 2026-11-18T09:21:00Z db1 postgres 4211 - [meta sequenceId=\"1\"] connection received\n<11>Nov 18 09:22:00 fw1 kernel: segfault at 0\n<999>bad pri\nSep 18 12:00:00 CEF:0|Example Security|Edge FW|1.2|4001|Port scan detected|8|src=203.0.113.9 dst=10.0.0.5 suser=alice\nCEF:0|Example Security|Edge FW|1.2|1002|Allowed connection|2|src=10.0.0.8\nCEF:0|Broken|Header|1.0|x\nthis is not a log line\n");
  assert.equal(typeof md, 'string');
  for (const s of ["3 of 16 lines with problems.", "| 12 | PRI 999 is above 191 | \\<999\\>bad pri |", "| 15 | the CEF header has 5 of 8 fields | CEF:0\\|Broken\\|Header\\|1.0\\|x |", "| 16 | the line matches no syslog or CEF format | this is not a log line |"]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportParse example 2", () => {
  const md = core.reportParse("Nov 18 09:12:01 web1 sshd[2210]: ok");
  assert.equal(typeof md, 'string');
  for (const s of ["# Parse Check", "All 1 line parsed."]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportSeverity example 1", () => {
  const md = core.reportSeverity("Nov 18 09:12:01 web1 sshd[2210]: Failed password for invalid user admin from 203.0.113.7 port 52211 ssh2\nNov 18 09:12:03 web1 sshd[2210]: Failed password for invalid user admin from 203.0.113.7 port 52213 ssh2\nNov 18 09:12:05 web1 sshd[2212]: Failed password for root from 203.0.113.7 port 52215 ssh2\nNov 18 09:12:07 web1 sshd[2214]: Failed password for root from 203.0.113.7 port 52217 ssh2\nNov 18 09:12:09 web1 sshd[2216]: Failed password for root from 203.0.113.7 port 52219 ssh2\nNov 18 09:15:22 web1 sshd[2301]: Accepted publickey for deploy from 198.51.100.4 port 40022 ssh2: ED25519 SHA256:abc\nNov 18 09:16:00 web1 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx\nNov  8 10:00:00 web1 CRON[3000]: (root) CMD (run-parts /etc/cron.hourly)\n<34>1 2026-11-18T09:20:00.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8\n<165>1 2026-11-18T09:21:00Z db1 postgres 4211 - [meta sequenceId=\"1\"] connection received\n<11>Nov 18 09:22:00 fw1 kernel: segfault at 0\n<999>bad pri\nSep 18 12:00:00 CEF:0|Example Security|Edge FW|1.2|4001|Port scan detected|8|src=203.0.113.9 dst=10.0.0.5 suser=alice\nCEF:0|Example Security|Edge FW|1.2|1002|Allowed connection|2|src=10.0.0.8\nCEF:0|Broken|Header|1.0|x\nthis is not a log line\n");
  assert.equal(typeof md, 'string');
  for (const s of ["| Severity | Lines |", "| critical | 1 |", "| error | 1 |", "| notice | 1 |", "| Facility | Lines |", "| user | 1 |", "| auth | 1 |", "| local4 | 1 |", "| Severity | Events |", "| Low | 1 |", "| High | 1 |"]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportSources example 1", () => {
  const md = core.reportSources("Nov 18 09:12:01 web1 sshd[2210]: Failed password for invalid user admin from 203.0.113.7 port 52211 ssh2\nNov 18 09:12:03 web1 sshd[2210]: Failed password for invalid user admin from 203.0.113.7 port 52213 ssh2\nNov 18 09:12:05 web1 sshd[2212]: Failed password for root from 203.0.113.7 port 52215 ssh2\nNov 18 09:12:07 web1 sshd[2214]: Failed password for root from 203.0.113.7 port 52217 ssh2\nNov 18 09:12:09 web1 sshd[2216]: Failed password for root from 203.0.113.7 port 52219 ssh2\nNov 18 09:15:22 web1 sshd[2301]: Accepted publickey for deploy from 198.51.100.4 port 40022 ssh2: ED25519 SHA256:abc\nNov 18 09:16:00 web1 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx\nNov  8 10:00:00 web1 CRON[3000]: (root) CMD (run-parts /etc/cron.hourly)\n<34>1 2026-11-18T09:20:00.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8\n<165>1 2026-11-18T09:21:00Z db1 postgres 4211 - [meta sequenceId=\"1\"] connection received\n<11>Nov 18 09:22:00 fw1 kernel: segfault at 0\n<999>bad pri\nSep 18 12:00:00 CEF:0|Example Security|Edge FW|1.2|4001|Port scan detected|8|src=203.0.113.9 dst=10.0.0.5 suser=alice\nCEF:0|Example Security|Edge FW|1.2|1002|Allowed connection|2|src=10.0.0.8\nCEF:0|Broken|Header|1.0|x\nthis is not a log line\n");
  assert.equal(typeof md, 'string');
  for (const s of ["| Host | Program | Lines | Errors or worse |", "| web1 | sshd | 6 | 0 |", "| db1 | postgres | 1 | 0 |", "| fw1 | kernel | 1 | 1 |", "| mymachine.example.com | su | 1 | 1 |", "| web1 | CRON | 1 | 0 |", "| web1 | sudo | 1 | 0 |", "| Vendor | Product | Events |", "| Example Security | Edge FW | 2 |", "| Signature | Name | Events |", "| 1002 | Allowed connection | 1 |", "| 4001 | Port scan detected | 1 |"]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportSecurity example 1", () => {
  const md = core.reportSecurity("Nov 18 09:12:01 web1 sshd[2210]: Failed password for invalid user admin from 203.0.113.7 port 52211 ssh2\nNov 18 09:12:03 web1 sshd[2210]: Failed password for invalid user admin from 203.0.113.7 port 52213 ssh2\nNov 18 09:12:05 web1 sshd[2212]: Failed password for root from 203.0.113.7 port 52215 ssh2\nNov 18 09:12:07 web1 sshd[2214]: Failed password for root from 203.0.113.7 port 52217 ssh2\nNov 18 09:12:09 web1 sshd[2216]: Failed password for root from 203.0.113.7 port 52219 ssh2\nNov 18 09:15:22 web1 sshd[2301]: Accepted publickey for deploy from 198.51.100.4 port 40022 ssh2: ED25519 SHA256:abc\nNov 18 09:16:00 web1 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx\nNov  8 10:00:00 web1 CRON[3000]: (root) CMD (run-parts /etc/cron.hourly)\n<34>1 2026-11-18T09:20:00.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8\n<165>1 2026-11-18T09:21:00Z db1 postgres 4211 - [meta sequenceId=\"1\"] connection received\n<11>Nov 18 09:22:00 fw1 kernel: segfault at 0\n<999>bad pri\nSep 18 12:00:00 CEF:0|Example Security|Edge FW|1.2|4001|Port scan detected|8|src=203.0.113.9 dst=10.0.0.5 suser=alice\nCEF:0|Example Security|Edge FW|1.2|1002|Allowed connection|2|src=10.0.0.8\nCEF:0|Broken|Header|1.0|x\nthis is not a log line\n");
  assert.equal(typeof md, 'string');
  for (const s of ["9 events.", "| Event | Count |", "| failed login | 3 |", "| failed login \\(invalid user\\) | 2 |", "| CEF High: Port scan detected | 1 |", "| accepted login | 1 |", "| su failure | 1 |", "| sudo | 1 |", "| Source | Failed attempts |", "| 203.0.113.7 | 5 |", "| Line | Time | Event | User | Source |", "| 1 | Nov 18 09:12:01 | failed login \\(invalid user\\) | admin | 203.0.113.7 |", "| 2 | Nov 18 09:12:03 | failed login \\(invalid user\\) | admin | 203.0.113.7 |", "| 3 | Nov 18 09:12:05 | failed login | root | 203.0.113.7 |"]) assert.ok(md.includes(s), 'missing: ' + s);
});

test("reportSecurity example 2", () => {
  const md = core.reportSecurity("Nov 18 09:12:01 web1 cron[1]: ok");
  assert.equal(typeof md, 'string');
  for (const s of ["# Security Events", "No security events found."]) assert.ok(md.includes(s), 'missing: ' + s);
});
