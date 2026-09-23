# SOC-2026-001 — SSH Authentication Investigation

> **Historical scenario narrative, not a verified real-event timeline.** Read the [retained evidence review](evidence-review.md) first. Counts, dates, baseline and authorization assertions below exceed the retained excerpt and must not be presented as observed facts. The original exercise is preserved for traceability.

## Purpose

Provide a repeatable procedure for Tier 1 SOC analysts to validate, investigate, classify, document, and escalate security alerts.

## 1. Alert Identification

- Alert ID: SOC-2026-001
- Timestamp: 2026-09-16 00:31:42 CEST
- Detection source: Linux authentication logs
- Detection rule: Multiple Failed SSH Authentication Attempts
- Severity: Medium
- Affected asset: srv-web-01
- Targeted accounts: admin, root, ubuntu
- Source IP: 10.10.20.45
- Destination IP: 10.10.20.10

## 2. Initial Validation

Determine:

- What triggered the alert? The alert was triggered by 47 failed SSH authentication attempts against srv-web-01 within a five-minute detection window.
- Which telemetry generated it? Linux authentication logs generated the telemetry used by the detection.
- Is the detection technically plausible? Yes. Repeated failed authentication attempts against TCP port 22 are consistent with unsuccessful SSH login attempts.

The attempts targeted multiple user accounts (admin, root, and ubuntu), which may be consistent with password guessing, credential testing, administrative activity, or an automated process.

No malicious intent can be established from the alert alone.
- Is the timestamp consistent? The alert reports activity at:

2026-09-16 00:31:42 CEST

Further validation against the underlying authentication log timestamps is required.
- Is the affected asset correctly identified? The affected asset is reported as:

srv-web-01 (10.10.20.10)

Further validation against asset inventory or host information is required.
- Is sufficient evidence available to begin triage? Yes.

Available evidence includes:

Source IP
Destination IP
Destination port
Target host
Target accounts
Number of failed attempts
Detection window
Authentication log source

However, additional log analysis is required to determine whether any SSH authentication attempt succeeded.

Do not assume malicious activity solely because an alert fired.

## 3. Context Collection

Collect relevant context:

- Asset hostname: srv-web-01
- Asset criticality: UNKNOWN
- Operating system: Ubuntu Linux
- User/account: admin, root and ubuntu
- Source and destination IP addresses: 10.10.20.45 / 10.10.20.10
- Source and destination ports: 22/TCP
- Protocol: SSH over TCP
- Process: UNKNOWN
- Parent process: UNKNOWN
- Command line: UNKNOWN
- Authentication events
- Network activity: UNKNOWN
- Related alerts: UNKNOWN / Not yet investigated

## 4. Investigation

### Evidence

The source 10.10.20.45 generated 47 failed SSH authentication
attempts against srv-web-01 within approximately five minutes.

The attempts targeted admin, root, and ubuntu. Authentication logs
identified admin as an invalid user.

At 00:31:11 CEST, password authentication for ubuntu from
10.10.20.45 succeeded and an SSH session was opened.

Asset inventory identified 10.10.20.45 as kali-redteam-01, an
authorized Security Engineering testing workstation. However, no
scheduled security test was identified for the relevant period and
authorization to access srv-web-01 remains unknown.

The ubuntu account does not normally authenticate from this source.
No successful SSH login from 10.10.20.45 was identified for ubuntu
during the previous 30 days.

Following the successful SSH login, failed sudo authentication events
were observed.

At 00:32:04 CEST, /usr/bin/cat /etc/shadow was executed with root
privileges. The system subsequently recorded a sudo session opened
for root(uid=0) by ubuntu(uid=1001).

### Timeline

- 00:27:03–00:31:04 — Repeated failed SSH authentication attempts.
- 00:31:11 — Successful SSH authentication for ubuntu.
- 00:31:11 — SSH session opened for ubuntu(uid=1001).
- 00:31:26 — Failed sudo attempt to execute /usr/bin/bash as root.
- 00:31:39 — Additional sudo authentication failure.
- 00:32:04 — /usr/bin/cat /etc/shadow executed as root.
- 00:32:04 — sudo session opened for root(uid=0) by ubuntu(uid=1001).
- 00:32:07 — sudo root session closed.
- 00:34:48 — SSH session closed.

### Indicators

- Source IP: 10.10.20.45
- Source host: kali-redteam-01
- Destination IP: 10.10.20.10
- Destination host: srv-web-01
- Service: SSH/22 TCP
- Accounts: admin, root, ubuntu
- Privileged file accessed: /etc/shadow

### Hypotheses

Primary hypothesis:

The activity may represent unauthorized password guessing followed by
successful use of the ubuntu account and subsequent privileged access.

Alternative hypothesis:

The activity may represent authorized Security Engineering testing
that was not recorded in the available scheduling information.

Authorization remains unresolved.

Observed behavior must not be treated as confirmed malicious activity
until authorization and operator context are established.

## 5. MITRE ATT&CK Mapping

- T1110.001 — Password Guessing
- T1021.004 — SSH
- Valid Accounts — candidate
- T1548.003 — Sudo and Sudo Caching
- T1003.008 — /etc/passwd and /etc/shadow

## 6. Disposition

Suspicious activity — authorization pending.

Compromise status: Not confirmed.

## 7. Severity Assessment

High.

Rationale:

The original failed-authentication alert was followed by successful
SSH authentication from an unusual source, sudo activity, successful
root-context execution, and access to /etc/shadow.

The source is an authorized Security Engineering workstation, which
provides a plausible benign explanation, but no scheduled test was
identified and authorization for this target remains unknown.

## 8. Decision

Escalate to Tier 2.

## 9. Analyst Justification

Tier 1 validated the authentication activity and identified successful
SSH access following repeated failures. Subsequent events demonstrate
successful privileged execution and access to /etc/shadow.

Tier 2 investigation is required to establish authorization, operator
identity, scope, credential exposure, and whether additional systems
or accounts were affected.

## 10. Escalation Package

When escalating, provide:

- Alert summary
- Relevant evidence
- Timeline
- Indicators
- Actions already performed
- ATT&CK mapping
- Current hypothesis
- Remaining questions

## 11. Lessons Learned

- Authentication logs were sufficient to reconstruct the core SSH and sudo timeline.
- Authorization context was the main missing evidence.
- Detection should correlate failed authentication, successful login, privilege escalation, and sensitive-file access.
- Tier 1 triage improves when asset ownership, scheduled testing, and normal login sources are immediately available.
