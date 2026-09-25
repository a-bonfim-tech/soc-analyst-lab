# SOC-2026-006 — EDR-to-SIEM Incident Lifecycle

## Executive summary

SOC-2026-006 demonstrates a controlled Tier 1 SOC workflow using Microsoft Defender for Endpoint, Microsoft Defender XDR and Microsoft Sentinel in an authorized disposable Windows laboratory environment.

Microsoft Defender for Endpoint generated genuine PowerShell-related detections. Defender XDR correlated the detections into an incident with vendor severity `Medium`. The investigation reviewed endpoint and user context, MITRE ATT&CK mapping, process relationships and PowerShell execution evidence.

Microsoft Defender Advanced Hunting was used against endpoint process telemetry. Microsoft Sentinel separately provided SIEM visibility into ingested endpoint, alert and incident telemetry, with KQL executed in the actual Sentinel workspace.

The reviewed evidence was consistent with the authorized Defender for Endpoint detection-test scenario. No reviewed evidence established unauthorized compromise. The analyst severity was reduced from `Medium` to `Informational`, and the incident was resolved without escalation or containment.

## SOC lifecycle demonstrated

`Endpoint telemetry → EDR detection → Alert → XDR incident → Ownership → Investigation → Enrichment → Severity decision → Analyst record → Resolution → Evidence`

## Detection and incident

- Detection source: Microsoft Defender for Endpoint EDR
- Detection context: PowerShell-related activity
- Correlation platform: Microsoft Defender XDR
- Vendor incident severity: `Medium`
- Initial analyst severity: `Medium`
- Final analyst severity: `Informational`
- Final analyst disposition: `False alert`
- Final status: `Resolved`
- Production impact: none — controlled laboratory scenario

Two genuine Defender for Endpoint PowerShell-related alerts were associated with the XDR incident.

## Tier 1 investigation

The investigation reviewed:

- alert metadata;
- affected endpoint context;
- user context;
- MITRE ATT&CK mapping;
- process relationships;
- PowerShell execution context;
- Defender Advanced Hunting endpoint telemetry;
- Microsoft Sentinel endpoint telemetry;
- Sentinel `SecurityAlert` visibility;
- Sentinel `SecurityIncident` visibility.

Defender Advanced Hunting and Microsoft Sentinel KQL are retained as separate evidence boundaries.

## SIEM and hunting evidence

Microsoft Defender Advanced Hunting returned relevant `DeviceProcessEvents` telemetry from the authorized laboratory endpoint during the investigation.

Microsoft Sentinel separately received Microsoft security telemetry through the configured integration. KQL was executed against `DeviceProcessEvents`, and Sentinel visibility of corresponding `SecurityAlert` and `SecurityIncident` records was retained.

Timestamped Sentinel and Defender Advanced Hunting executions performed after incident resolution are explicitly documented as post-closure evidence validation and are not represented as pre-closure investigative actions.

## Severity and disposition

The Microsoft platform severity remained `Medium`.

The analyst initially treated the case as `Medium` while the alert context was investigated. After correlation with the authorized laboratory scenario and review of the retained evidence, the final analyst severity was `Informational`.

The resolved Defender XDR interface displayed the classification `False alert`.

The retained XDR activity export separately records determination `Not malicious` and classification `False positive`. These are preserved as distinct platform-generated terms and are not normalized into a single raw value.

## Escalation and containment

No material evidence reviewed during the investigation required Tier 2 escalation.

No containment action was performed. The activity occurred on an authorized disposable laboratory endpoint and the reviewed evidence did not establish unauthorized compromise.

## Evidence integrity

The repository retains:

- alert record;
- Tier 1 investigation record;
- findings;
- laboratory ticket lifecycle;
- platform-event timeline;
- executed KQL;
- Defender Advanced Hunting evidence documentation;
- Sentinel alert evidence documentation;
- Sentinel incident evidence documentation;
- authorization and execution-boundary documentation;
- SHA-256 evidence manifest.

Raw Defender and Microsoft Sentinel exports remain private. Unnecessary tenant, subscription, workspace, device, user, alert and incident identifiers are excluded from the public repository.

## Evidence limitation

A separate contemporaneous record containing the exact formal start and end of the EDR test execution window was not retained.

The first alert timestamp is not substituted for the test execution time, and later filesystem/export timestamps are not represented as execution timestamps.

Accordingly, the scenario contract formal test-window correlation gate cannot be independently demonstrated retrospectively.

This limitation does not rewrite the platform-generated alerts, incident, telemetry, investigation, disposition or resolution. It remains an explicit evidence gap.

## Scope boundary

This case demonstrates hands-on SOC investigation and evidence handling in a controlled laboratory using real Microsoft security platforms.

It does not claim:

- production SOC employment;
- customer incident handling;
- enterprise-scale operations;
- 24x7 monitoring experience;
- production containment authority;
- production Microsoft Sentinel or Defender administration;
- a real attacker or malware incident.

## Outcome

SOC-2026-006 provides retained evidence of an end-to-end laboratory SOC workflow from genuine endpoint detection through XDR correlation, SIEM investigation, analyst triage, severity reassessment, documented disposition and incident resolution.

The case remains subject to the explicitly documented formal execution-window evidence gap and must not be represented as satisfying every mandatory scenario-contract gate.
