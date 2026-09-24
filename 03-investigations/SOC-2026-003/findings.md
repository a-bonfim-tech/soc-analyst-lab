# SOC-2026-003 — Findings

## Finding 1 — PowerShell execution was independently corroborated

Windows Security Event ID 4688 and Sysmon Event ID 1 independently recorded the
controlled PowerShell process activity.

**Assessment:** FACT within the retained evidence.

## Finding 2 — Encoded execution was inspectable

PowerShell Operational Event ID 4104 exposed the harmless payload associated with
the controlled `-EncodedCommand` execution.

Encoding alone was therefore not treated as evidence of malicious intent.

**Assessment:** malicious encoded execution not supported.

## Finding 3 — Registry activity did not establish persistence

Sysmon Event IDs 12/13 recorded temporary Registry activity. The retained evidence
identifies the value as a benign lab marker rather than an autostart configuration.

**Assessment:** persistence not established.

## Finding 4 — File creation did not establish malware activity

Sysmon Event ID 11 recorded creation of a temporary marker file. Cleanup activity
was subsequently observed.

**Assessment:** malicious file activity not established.

## Finding 5 — Multi-source correlation supports the authorized explanation

Security, Sysmon and PowerShell telemetry describe temporally aligned parts of the
same controlled sequence. Explicit SOC003 markers and known activity context support
the authorized laboratory explanation.

**Assessment:** authorized benign lab activity supported with high confidence within
the evidence scope.

## Decision

Initial laboratory triage priority: **Medium**.

Post-investigation severity: **Low**.

Disposition: **Close as authorized benign laboratory activity.**

Tier 2 escalation is not required for the completed scenario. Escalation would be
appropriate if authorization could not be established or if additional evidence
supported malicious execution, persistence, credential compromise, broader scope or
material impact.

No containment was performed.
