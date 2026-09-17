# SOC-2026-001 — Tier 1 Escalation

## Status

Escalated to Tier 2

## Recommended Severity

High

## Classification

Suspicious activity — authorization pending

## Compromise Status

Not confirmed

## Executive Summary

Multiple failed SSH authentication attempts from 10.10.20.45
(kali-redteam-01) against srv-web-01 were followed by successful
password authentication to the ubuntu account.

The source host is an authorized Security Engineering testing
workstation, but no scheduled security test was identified for the
relevant period and authorization to access srv-web-01 remains unknown.

Following successful SSH authentication, the session generated failed
sudo authentication events and subsequently executed
/usr/bin/cat /etc/shadow with root privileges.

The activity requires Tier 2 investigation to determine authorization,
scope, credential exposure, and potential compromise.

## Key Evidence

- 47 failed SSH authentication attempts within approximately five minutes.
- Source: 10.10.20.45 (kali-redteam-01).
- Targets included admin, root, and ubuntu.
- admin was reported as an invalid user.
- Successful password authentication to ubuntu at 00:31:11 CEST.
- SSH session opened for ubuntu(uid=1001).
- Source IP was not observed as a successful SSH source for ubuntu during the previous 30 days.
- No scheduled security test was identified for the relevant period.
- Failed sudo activity occurred after SSH authentication.
- /usr/bin/cat /etc/shadow was subsequently executed as root.
- Root sudo session was successfully opened.
- SSH session closed at 00:34:48 CEST.

## Timeline

00:27:03–00:31:04
Repeated failed SSH authentication attempts.

00:31:11
Successful SSH password authentication for ubuntu.
SSH session opened.

00:31:26
Failed sudo attempt to execute /usr/bin/bash as root.

00:31:39
Additional sudo authentication failure.

00:32:04
/usr/bin/cat /etc/shadow executed as root.
sudo root session opened.

00:32:07
sudo root session closed.

00:34:48
SSH session closed.

## ATT&CK Candidates

- T1110.001 — Password Guessing
- T1021.004 — SSH
- Valid Accounts — candidate
- T1548.003 — Sudo and Sudo Caching
- T1003.008 — /etc/passwd and /etc/shadow

## Outstanding Questions

- Was the activity explicitly authorized?
- Who controlled kali-redteam-01 during the incident?
- How was successful sudo authorization obtained?
- Was the content of /etc/shadow copied or transferred?
- What additional commands were executed?
- Was persistence established?
- Were other systems accessed?
- Was kali-redteam-01 itself compromised?
- Were additional credentials exposed?

## Tier 1 Recommendation

Escalate to Tier 2 for authorization verification, expanded log
correlation, host investigation, credential exposure assessment,
and determination of incident scope.
