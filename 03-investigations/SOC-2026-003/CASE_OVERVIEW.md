# SOC-2026-003 — Windows Endpoint Investigation

![SOC-2026-003 Windows Endpoint Investigation](../../assets/soc-2026-003-case-overview.svg)

> **REAL CONTROLLED LAB** | Windows endpoint telemetry | Initial priority: **Medium** | Final severity: **Low** | Disposition: **Authorized benign laboratory activity**

## 30-second case review

**Signal**

Suspicious-looking PowerShell execution, including an encoded invocation, occurred together with Registry and file activity on an authorized disposable Windows laboratory endpoint.

**Evidence correlated**

| Source | Event IDs | Analyst use |
|---|---:|---|
| Windows Security | 4688 | Independent process-creation evidence |
| Sysmon | 1 | Corroborated PowerShell process execution |
| PowerShell Operational | 4103, 4104 | Command and script-block context |
| Sysmon | 12, 13 | Registry creation and value modification |
| Sysmon | 11 | File-creation evidence |

**Investigation path**

`PowerShell signal → multi-source correlation → encoded-content review → Registry/file analysis → timeline reconstruction → hypothesis testing → severity reassessment → disposition`

## Analyst decision

The encoded PowerShell invocation was suspicious in isolation, but retained PowerShell telemetry exposed a harmless controlled payload.

Registry activity was investigated for possible persistence. The observed value was a temporary laboratory marker rather than an autostart configuration.

File creation was investigated for possible malicious activity. The retained evidence identified a temporary laboratory marker and subsequent cleanup.

Multi-source telemetry therefore supported the authorized controlled-lab explanation with high confidence within the evidence scope.

**Initial laboratory triage priority:** Medium
**Post-investigation severity:** Low
**Disposition:** Close as authorized benign laboratory activity
**Tier 2 escalation:** Not required for the completed scenario

## Evidence chain

[Full investigation](investigation.md) → [Timeline](timeline.csv) → [Findings](findings.md) → [Disposition](escalation.md) → [Public correlation evidence](../../10-evidence/SOC-2026-003/windows-endpoint-correlation.md)

## What this demonstrates

- Windows endpoint investigation
- multi-source telemetry correlation
- PowerShell analysis
- Registry and file-event analysis
- timeline reconstruction
- competing-hypothesis testing
- evidence-bounded severity reassessment
- documented closure and escalation criteria

## Evidence boundary

This case demonstrates work performed in an **authorized controlled laboratory**. It does not establish production SOC employment, enterprise EDR/XDR detection, Microsoft Sentinel execution, production SIEM alert creation, malicious intent, compromise, persistence, malware execution or production containment.
