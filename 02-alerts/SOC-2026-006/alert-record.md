# SOC-2026-006 — Alert Operational Record

## Case

- Case ID: `SOC-2026-006`
- Environment: authorized disposable Windows laboratory endpoint
- Detection source: Microsoft Defender for Endpoint EDR
- Correlation platform: Microsoft Defender XDR
- SIEM visibility: Microsoft Sentinel
- Production impact: none — controlled laboratory scenario

## Defender alerts

Two genuine Defender-generated PowerShell-related alerts were associated with the investigated activity:

1. `Suspicious PowerShell command line` — vendor severity `Medium`
2. `[Test Alert] Suspicious Powershell commandline` — vendor severity `Informational`

Microsoft Defender XDR correlated the alerts into the investigated incident.

## Incident state

- Vendor incident severity: `Medium`
- Initial analyst triage severity: `Medium`
- Final analyst severity: `Informational / benign authorized test activity`
- Final analyst disposition: `False alert`
- Final incident status: `Resolved`

The vendor severity is preserved separately from the analyst assessment.

## Analyst workflow

`Alert → Ownership → Triage → Investigation → Enrichment → Severity decision → Analyst record → Resolution`

The investigation reviewed alert metadata, affected endpoint context, user context, MITRE ATT&CK mapping, process relationships and PowerShell execution context.

Microsoft Defender Advanced Hunting was used against endpoint process telemetry. Microsoft Sentinel was separately used to review ingested endpoint, alert and incident telemetry through KQL.

## Decision

The reviewed evidence was consistent with the authorized Microsoft Defender for Endpoint detection-test activity on the disposable laboratory endpoint.

No evidence reviewed within the investigation scope established an unauthorized compromise.

The incident was therefore resolved in Microsoft Defender XDR with the interface classification `False alert`.

The retained XDR activity export separately records `False positive` and determination `Not malicious`. These values are preserved as distinct platform terminology and are not silently treated as interchangeable.

## Evidence limitation

A separate contemporaneous record of the exact formal EDR test execution window was not retained.

The first alert timestamp is not substituted for the test execution time, and later export timestamps are not treated as execution timestamps.

Accordingly, the repository does not claim that the scenario contract's formal test-window correlation gate was fully satisfied.

## Evidence boundary

- Controlled laboratory evidence only.
- No production or customer SOC activity is claimed.
- Raw Defender and Sentinel exports remain private.
- Unnecessary tenant, subscription, workspace, device, user, alert and incident identifiers are excluded from this public record.
- Defender Advanced Hunting and Microsoft Sentinel KQL remain separate evidence boundaries.
- Post-closure validation queries are not represented as pre-closure investigative actions.
