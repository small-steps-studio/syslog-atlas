# Reports

Every report reads the text of the active editor and opens its result as a new Markdown document. Your file is never changed and nothing is sent anywhere. The examples below come from the sample file (Open Sample File).

## Show Log Summary

Command: **Syslog Atlas: Show Log Summary**

Counts the lines per format (RFC 5424, BSD, CEF, unknown) and the distinct hosts, gives the first and last timestamp in file order and lists the 10 programs with the most lines.

Example (sample file):

> # Log Summary
>
> 15 lines from 3 hosts.
>
> | Format | Lines |
> | --- | ---: |
> | RFC 5424 | 2 |
> | BSD | 12 |
> | unknown | 1 |
>
> First entry: Nov 18 09:12:01 (line 1). Last entry: Nov 18 09:25:00 (line 14).
>
> | Program | Lines |
> | --- | ---: |
> | sshd | 6 |
> | CEF | 3 |
> | CRON | 1 |
> | kernel | 1 |
> | postgres | 1 |
> | su | 1 |
> | sudo | 1 |

## Show Parse Check

Command: **Syslog Atlas: Show Parse Check**

Lists every line that cannot be read, with the reason: a PRI above 191, text after the PRI that is neither RFC 5424 nor BSD syslog, a CEF header with fewer than 8 fields, a CEF severity outside 0 to 10, or no known format at all.

Example (sample file):

> # Parse Check
>
> 1 of 15 lines with problems.
>
> | Line | Problem | Text |
> | ---: | --- | --- |
> | 15 | the line matches no syslog or CEF format | garbled line from a broken forwarder |

## Show Severity Overview

Command: **Syslog Atlas: Show Severity Overview**

Counts the lines per syslog severity (emergency to debug) and facility (kern to local7) from their PRI values, and the CEF events per level (Low 0-3, Medium 4-6, High 7-8, Very-High 9-10).

Example (sample file):

> # Severity Overview
>
> ## Syslog severity
>
> | Severity | Lines |
> | --- | ---: |
> | critical | 1 |
> | error | 1 |
> | notice | 1 |
>
> ## Facility
>
> | Facility | Lines |
> | --- | ---: |
> | user | 1 |
> | auth | 1 |
> | local4 | 1 |
>
> ## CEF severity
>
> No CEF events.

## Show Sources (Pro)

Command: **Syslog Atlas: Show Sources** (Pro; part of the 14-day trial)

Lists every host and program pair with its number of lines and of lines with severity error or worse, every CEF device (vendor and product) with its number of events, and the 20 most frequent CEF signatures.

Example (sample file):

> # Sources
>
> ## Hosts and programs
>
> | Host | Program | Lines | Errors or worse |
> | --- | --- | ---: | ---: |
> | web1 | sshd | 6 | 0 |
> | fw1 | CEF | 3 | 0 |
> | db1.example.test | postgres | 1 | 0 |
> | db1.example.test | su | 1 | 1 |
> | fw1 | kernel | 1 | 1 |
> | web1 | CRON | 1 | 0 |
> | web1 | sudo | 1 | 0 |
>
> ## CEF devices
>
> No CEF events.

## Show Security Events (Pro)

Command: **Syslog Atlas: Show Security Events** (Pro; part of the 14-day trial)

Finds failed and accepted SSH logins, invalid users, sudo commands, PAM authentication failures, su failures and CEF events with severity 7 or higher, counts them per kind, lists the sources with 5 or more failed attempts as possible brute force, and lists every event with its line, time, user and source.

Example (sample file):

> # Security Events
>
> 8 events.
>
> | Event | Count |
> | --- | ---: |
> | failed login | 3 |
> | failed login \(invalid user\) | 2 |
> | accepted login | 1 |
> | su failure | 1 |
> | sudo | 1 |
>
> ## Possible brute force
>
> | Source | Failed attempts |
> | --- | ---: |
> | 203.0.113.7 | 5 |
>
> ## Events
>
> | Line | Time | Event | User | Source |
> | ---: | --- | --- | --- | --- |
> | 1 | Nov 18 09:12:01 | failed login \(invalid user\) | admin | 203.0.113.7 |
> | 2 | Nov 18 09:12:03 | failed login \(invalid user\) | admin | 203.0.113.7 |
