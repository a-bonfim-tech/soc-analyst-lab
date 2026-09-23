# SOC-2026-004 — findings (synthetic)

| Evidence | Interpretation | Conclusion | Confidence |
|---|---|---|---|
| SEC-006–010: failures, then type 10 success outside supplied admin baseline, same host/account/source; 4672 matches session | Administrative access merits authorization review | Privileged session observed; account compromise unconfirmed | High observation; low compromise |
| SYS-005: PowerShell, Office parent, encoded command, matching session | Unusual execution path; automation is an alternative | Candidate T1059.001 behavior, not proof of malware | High execution representation; low maliciousness |
| SYS-007: matching process GUID, user Run value and public executable path | Autostart mechanism configured in writable location | T1547.001 configuration represented; execution at logon unproven | High configuration; no execution evidence |
| SYS-006: same GUID to TEST-NET endpoint, port 443 | Process-associated network activity | No C2 or exfiltration conclusion | High correlation; low purpose |

## Negative/control evidence

SEC-002/003 provide an approved admin session. SEC-011/012 represent routine SYSTEM
service privileges. SEC-013 is a nonprivileged remote logon. SYS-002 is ordinary
administration; SYS-004 has an Office parent without encoding; SYS-009 is encoded
maintenance without Office ancestry. SYS-003 is a conventional Run value; SYS-008
is a public path outside the Run key. These should not match the three conditions.

These controls are designed examples, not a measurement of production false-positive
rate. A legitimate program installed in AppData can still match the registry rule.
Unusual administrator activity outside the baseline can still be authorized.

## Decision

Escalate the combined sequence, preserve artifacts and validate authorization.
Do not assert initial access, privilege escalation, data theft or actor identity.
See the [investigation](investigation.md) and [escalation](escalation.md).
