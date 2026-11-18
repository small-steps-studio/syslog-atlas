'use strict';
// The sample files of the Open Sample commands. All data is invented for this product; it names no real company, person or system.

const SAMPLES = {
 "openSample": {
  "title": "Open Sample File",
  "fileName": "server-mixed.log",
  "languageId": "log",
  "text": "Nov 18 09:12:01 web1 sshd[2210]: Failed password for invalid user admin from 203.0.113.7 port 52211 ssh2\nNov 18 09:12:03 web1 sshd[2210]: Failed password for invalid user admin from 203.0.113.7 port 52213 ssh2\nNov 18 09:12:05 web1 sshd[2212]: Failed password for root from 203.0.113.7 port 52215 ssh2\nNov 18 09:12:07 web1 sshd[2214]: Failed password for root from 203.0.113.7 port 52217 ssh2\nNov 18 09:12:09 web1 sshd[2216]: Failed password for root from 203.0.113.7 port 52219 ssh2\nNov 18 09:15:22 web1 sshd[2301]: Accepted publickey for deploy from 198.51.100.4 port 40022 ssh2: ED25519 SHA256:abc\nNov 18 09:16:00 web1 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx\nNov 18 09:17:00 web1 CRON[3000]: (root) CMD (run-parts /etc/cron.hourly)\n<34>1 2026-11-18T09:20:00.003Z db1.example.test su - ID47 - 'su root' failed for lonvick on /dev/pts/8\n<165>1 2026-11-18T09:21:00Z db1.example.test postgres 4211 - [meta sequenceId=\"1\"] connection received\n<11>Nov 18 09:22:00 fw1 kernel: segfault at 0 ip 00007f\nNov 18 09:23:00 fw1 CEF:0|Example Security|Edge FW|2.1|4001|Port scan detected|8|src=203.0.113.9 dst=10.0.0.5\nNov 18 09:24:00 fw1 CEF:0|Example Security|Edge FW|2.1|1002|Allowed connection|2|src=10.0.0.8 dst=10.0.0.5\nNov 18 09:25:00 fw1 CEF:0|Example Security|Web Proxy|1.0|7|Blocked URL\ngarbled line from a broken forwarder\n"
 }
};

/** The sample with the given id, or null. */
function sampleFor(id) { return SAMPLES[id] || null; }

module.exports = { sampleFor: sampleFor, SAMPLE_IDS: Object.keys(SAMPLES) };
