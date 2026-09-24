# SOC-2026-003 — real Windows endpoint telemetry status

The previously documented Windows telemetry gap is now closed for the defined
laboratory scope.

Real endpoint-generated Windows Security, Sysmon and PowerShell Operational
telemetry was collected from the authorized disposable Windows lab. The collection
was transferred with SHA-256 verification, baseline/final evidence integrity was
validated, and the final package was normalized for analysis.

Raw endpoint evidence remains private because it contains endpoint-specific
identifiers. The public repository contains collection and ingestion tooling plus
sanitized derived evidence and analyst documentation.

Public evidence:
- `10-evidence/SOC-2026-003/windows-endpoint-correlation.md`
- `03-investigations/SOC-2026-003/investigation.md`
- `03-investigations/SOC-2026-003/timeline.csv`
- `03-investigations/SOC-2026-003/findings.md`
- `03-investigations/SOC-2026-003/escalation.md`

This closes the earlier real-Windows-telemetry publication gap. It does not convert
the exercise into production SOC experience, a real enterprise incident, or
commercial SIEM/EDR experience.
