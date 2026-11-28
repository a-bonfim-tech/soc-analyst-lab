# Evidence

Evidence suitable for version control after sanitization or explicit publication
review.

## Evidence and telemetry categories

The README headline counts **9 evidence/telemetry categories**. Each row below
names one category, the case that uses it and the retained public evidence.
`tests/test_readme_claims.py` fails if the headline and this table diverge or
if a linked path does not exist.

| # | Category | Case | Public evidence | Provenance |
|---|---|---|---|---|
| 1 | Linux authentication logs | SOC-2026-001 | [real-lab-auth.txt](SOC-2026-001/real-lab-auth.txt) | Retained lab excerpt, sanitized |
| 2 | Cloud identity sign-in logs | SOC-2026-002 | [signinlogs-synthetic.csv](SOC-2026-002/signinlogs-synthetic.csv) | Synthetic |
| 3 | Windows Security Event Log | SOC-2026-003 | [windows-endpoint-correlation.md](SOC-2026-003/windows-endpoint-correlation.md) | Real endpoint-generated lab telemetry, sanitized |
| 4 | Sysmon | SOC-2026-003 | [windows-endpoint-correlation.md](SOC-2026-003/windows-endpoint-correlation.md) | Real endpoint-generated lab telemetry, sanitized |
| 5 | PowerShell logging | SOC-2026-003 | [windows-endpoint-correlation.md](SOC-2026-003/windows-endpoint-correlation.md) | Real endpoint-generated lab telemetry, sanitized |
| 6 | Network traffic (PCAP with TShark, Zeek logs) | SOC-2026-005 | [network-traffic/README.md](SOC-2026-005/network-traffic/README.md) | Real controlled lab |
| 7 | EDR/XDR alerts and endpoint hunting (Microsoft Defender for Endpoint, Defender XDR, Advanced Hunting) | SOC-2026-006 | [defender-advanced-hunting.md](SOC-2026-006/defender-advanced-hunting.md) | Genuine Defender detections, authorized disposable lab |
| 8 | SIEM (Microsoft Sentinel) | SOC-2026-006 | [sentinel-securityalert.md](SOC-2026-006/sentinel-securityalert.md) | Authorized disposable lab |
| 9 | Email message and authentication headers | SOC-2026-007 | [suspicious-email.eml](SOC-2026-007/suspicious-email.eml) | Synthetic / controlled lab |

Windows Security and PowerShell telemetry also appear as synthetic fixtures in
SOC-2026-004; that case adds no new category.

## SOC-2026-005 — network traffic evidence

The [SOC-2026-005 network evidence package](SOC-2026-005/network-traffic/README.md)
contains a publication-reviewed controlled-lab PCAP, TShark HTTP extraction,
Zeek connection/HTTP/file telemetry, checksum-diagnostic evidence, capture
metadata, tool versions and SHA256 integrity records.

The package is **REAL CONTROLLED LAB** evidence. It does not represent production
SOC traffic, customer traffic, malware execution or real command-and-control.

Sensitive or unreviewed raw evidence must remain outside the Git repository.
Raw artifacts may be retained only when the case documentation establishes an
appropriate controlled evidence boundary and publication review.
