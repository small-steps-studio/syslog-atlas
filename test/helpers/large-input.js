'use strict';
// Builds a log text of about `bytes` characters for the large-file test (invented lines).
function make(bytes) {
  const parts = []; let size = 0, i = 0;
  while (size < bytes) {
    const s = (i % 4 === 0 ? 'Nov 18 10:00:00 web' + (i % 9) + ' sshd[' + i + ']: Failed password for root from 203.0.113.' + (i % 200) + ' port ' + (i % 60000) + ' ssh2'
      : i % 4 === 1 ? '<34>1 2026-11-18T10:00:00Z db' + (i % 5) + ' app ' + i + ' - - message ' + 'x'.repeat(60)
      : i % 4 === 2 ? 'Nov 18 10:00:00 fw1 CEF:0|Example|FW|1|' + (i % 50) + '|Event ' + (i % 50) + '|' + (i % 11) + '|src=10.0.' + (i % 255) + '.1'
      : 'Nov 18 10:00:00 web1 CRON[' + i + ']: (root) CMD (job)') + '\n';
    parts.push(s); size += s.length; i++;
  }
  return parts.join('');
}
module.exports = { make };
