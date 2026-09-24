# SOC-2026-004 — synthetic Windows detection investigation

**Flagship reproducible case — synthetic only.** Independently authored fixtures;
no Windows collection, real incident, customer system or production SOC response.
SOC-2026-003 is the separate real-endpoint-telemetry laboratory track.

## Alert and disposition

| Field | Value |
|---|---|
| Alert | SYN-004-PS-01; Office-parent encoded PowerShell candidate |
| Event time | 2026-09-23 09:02:00 UTC (SYS-005) |
| Source | Synthetic Sysmon process creation; local regression evaluator |
| Initial severity | Medium, single suspicious process behavior |
| Correlated severity | High triage priority within this lab rubric |
| Asset | SYN-WIN-04, Windows workstation, synthetic finance operations, medium criticality |
| Account/session | SYNTH\ops.admin / 0x900 |
| Disposition | Escalate to Tier 2; authorization and compromise unconfirmed |
| Confidence | High in fixture correlations; moderate in need to investigate; low in malicious intent |

There is no real alert receipt time, SLA, EDR verdict or automated incident creation.
The alert is a deterministic match against supplied data, not a live SIEM alert.

## Initial triage

1. Confirm [dataset provenance and schema](../../02-datasets/soc-2026-004/README.md).
2. Review SYS-005 rather than assuming encoded content means malware.
3. Correlate Computer + LogonId with SEC-009/010. Confirm account context in
   asset-context.json. The approved administrative source is 192.0.2.10;
   the observed 198.51.100.24 is outside that supplied baseline.
4. Follow Computer + ProcessGuid from SYS-005 to SYS-006/007.
5. Compare benign controls before deciding severity. Do not infer causality from
   timestamps alone. [Findings](findings.md) separate observations from interpretation.

## Evidence and minimum defensible timeline

| UTC | Records | Observation |
|---|---|---|
| 08:05:00–01 | SEC-002/003 | Approved-source admin RemoteInteractive logon and special privileges |
| 09:00:00–20 | SEC-006/007/008 | Three failed remote logons for the same account/source |
| 09:01:00–01 | SEC-009/010 | Successful type 10 logon; special privileges assigned to matching session |
| 09:02:00 | SYS-005 | PowerShell creation, Office parent, encoded command, session 0x900 |
| 09:02:05 | SYS-006 | Same process GUID observed with destination 203.0.113.80:443 |
| 09:02:30 | SYS-007 | Same process GUID sets a user Run value referencing a public-directory executable |

The full [23-event timeline](timeline.csv) retains benign context and original
fields. [Automation](../../05-automation/build_timeline.py) normalizes time and
links exact identifiers; it does not infer an attack or fill missing evidence.
Logon IDs are host/boot scoped; this fixture covers one host and one short session
window with no reboot. Real ingestion requires boot/session lifetime disambiguation.

## Analysis boundaries

- Security 4624 type 10 supports remote interactive authentication, not identity of
  the person operating the account. Three failures do not prove brute force.
- 4672 shows assigned special privileges, not an elevation exploit or their use.
- Sysmon 1 provides process/parent/session context. No Office document, hash,
  script-block log, signature or user testimony establishes the initial vector.
- Sysmon 13 supports a configured Run value. The executable was not acquired;
  existence and subsequent autostart execution are unproven.
- Sysmon 3 supports a connection observation. No payload, DNS or proxy evidence
  supports C2 attribution, exfiltration or a remote service identity.

## Competing explanations and gaps

An authorized but undocumented maintenance session could explain the source,
PowerShell and Run value. A user automation workflow could explain Office ancestry.
Account misuse is another hypothesis. The benign approved admin session and normal
Run entry demonstrate that these mechanisms are not intrinsically malicious.

Missing: authorization/change ticket, actual script-block events, document,
file/signature/hash, registry export, memory, EDR lineage, packet capture, domain
controller authentication and host clock/boot evidence. Fixture completeness is
not real-world collection completeness. No attribution or malware family claimed.

## Severity and action

High means prompt Tier 2 review in this lab: a privileged remote session outside
baseline is associated with suspicious execution and a persistent configuration
change on the same host. Medium asset criticality and unconfirmed impact prevent
an automatic critical rating. Positive change validation could reduce priority;
confirmed unauthorized activity or broader scope could increase it.

[Tier 2 package](escalation.md) lists evidence-preserving collection and conditional
containment. No isolation, credential reset, process kill or registry deletion was
performed. [Coverage](../../04-detection-rules/ATTACK-COVERAGE.md) scopes ATT&CK claims.
[Validation](../../07-lab/detection-tests/SOC-2026-004/README.md) distinguishes local
fixture testing from Sigma backend and KQL runtime execution.

## Primary references

- [Microsoft Sysmon event semantics](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft 4672 and Logon ID correlation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [Microsoft 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [MITRE PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE Valid Accounts](https://attack.mitre.org/techniques/T1078/)

References checked 2026-09-23. Technique descriptions classify behavior; they do not
independently establish malicious intent in this synthetic case.
