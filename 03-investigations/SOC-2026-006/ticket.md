# SOC-2026-006 — Analyst Ticket

## Case

- Case ID: SOC-2026-006
- Environment: Authorized disposable Windows laboratory endpoint
- Platforms: Microsoft Defender for Endpoint, Microsoft Defender XDR, Microsoft Sentinel
- Detection source: EDR
- Vendor incident severity: Medium
- Final analyst disposition: False alert
- Final status: Resolved
- Production impact: None — controlled laboratory scenario

## Lifecycle

| State | Evidence-backed analyst action |
|---|---|
| NEW | Microsoft Defender for Endpoint generated PowerShell-related alerts and Microsoft Defender XDR correlated them into an incident. |
| TRIAGE | Incident ownership was assigned and the case was moved to In Progress. Alert metadata, affected endpoint, user context, MITRE ATT&CK mapping and process evidence were reviewed. |
| INVESTIGATING | Process-tree evidence and PowerShell execution context were reviewed. Defender Advanced Hunting was executed against endpoint telemetry. Microsoft Sentinel KQL was executed against ingested DeviceProcessEvents telemetry. |
| DECISION | Evidence was consistent with the authorized Microsoft Defender for Endpoint detection-test activity on the disposable lab endpoint. No evidence reviewed in this investigation established an unauthorized compromise. |
| CLOSED | Incident classified as False alert and changed to Resolved after analyst documentation was recorded in Microsoft Defender XDR. |

## Evidence-backed timeline

| Timestamp (UTC) | Recorded event |
|---|---|
| 2026-09-25 01:34:31.436 | First PowerShell-related alert linked to the Microsoft XDR incident. |
| 2026-09-25 01:35:38.193 | Second PowerShell-related alert linked to the incident. |
| 2026-09-25 02:46:35.713 | Incident assignment recorded. |
| 2026-09-25 02:49:14.906 | Incident status changed from `Active` to `In Progress`. |
| 2026-09-25 17:05:58.895 | Tier 1 triage/investigation comment recorded after evidence review. |
| 2026-09-25 17:09:35.180 | XDR recorded determination `Not malicious` and classification `False positive`. |
| 2026-09-25 17:11:54.116 | Incident status changed from `In Progress` to `Resolved`; resolution comment recorded. |

These timestamps are taken from the retained Microsoft Defender XDR incident-activity export. They represent recorded platform events, not inferred start or completion times for every analytical step.

### Classification terminology

The retained XDR activity export records the classification transition as `False positive` and the determination as `Not malicious`. The incident interface subsequently displayed the resolved incident classification as `False alert`. Both observations are retained as platform terminology; they are not treated as interchangeable raw values.

## Severity assessment

- Microsoft/vendor severity: Medium
- Initial analyst triage severity: Medium
- Final analyst severity: Informational / benign authorized test activity

The vendor severity is retained separately from the analyst's final assessment. The final assessment reflects the investigated laboratory context and does not modify the historical vendor-assigned severity.

## Investigation summary

The case began with genuine Microsoft Defender for Endpoint detections associated with suspicious PowerShell behavior on an authorized disposable Windows laboratory endpoint.

Microsoft Defender XDR correlated the detections into an incident. The investigation reviewed alert metadata, endpoint and user context, MITRE ATT&CK mapping, process relationships, command execution context and available enrichment.

Defender Advanced Hunting was used to query endpoint process telemetry. Microsoft Sentinel separately received endpoint telemetry through the configured Microsoft security integration, and KQL was executed in the actual Sentinel workspace against DeviceProcessEvents.

The observed activity was reconciled with the authorized Microsoft Defender for Endpoint detection-test scenario. Based on the retained evidence reviewed for this case, the incident was classified as False alert and resolved.

## Evidence boundaries

- This is controlled laboratory evidence, not production SOC experience.
- Raw Defender and Sentinel CSV exports are retained privately and are not committed to this repository.
- Tenant, subscription, workspace, device and user identifiers that are unnecessary for public verification must remain excluded or sanitized.
- Defender Advanced Hunting execution and Microsoft Sentinel KQL execution are separate evidence boundaries and must not be conflated.
- No claim is made that absence of observed malicious activity proves absence of all malicious activity outside the investigated evidence scope.
