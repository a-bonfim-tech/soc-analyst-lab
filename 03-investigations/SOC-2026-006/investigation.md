# SOC-2026-006 — Investigation

## Scope

This investigation documents Tier 1 analysis of genuine Microsoft Defender for Endpoint PowerShell-related detections generated on an authorized disposable Windows laboratory endpoint.

Microsoft Defender XDR correlated the detections into an incident. Microsoft Sentinel provided separate SIEM visibility into ingested Microsoft security telemetry.

This is a controlled laboratory investigation and does not represent production SOC or customer incident-handling experience.

## Detection and triage

Microsoft Defender for Endpoint generated two PowerShell-related alerts that were associated with the Microsoft Defender XDR incident.

The incident carried Microsoft/vendor severity `Medium`.

During triage, the analyst reviewed:

- alert metadata;
- affected endpoint context;
- user context;
- MITRE ATT&CK mapping;
- process relationships;
- PowerShell execution context;
- available enrichment.

Incident ownership was recorded and the incident was moved from `Active` to `In Progress`.

The initial analyst triage severity was `Medium`.

## Investigation

Process-tree evidence and PowerShell execution context were reviewed in Microsoft Defender XDR.

Microsoft Defender Advanced Hunting was executed against `DeviceProcessEvents` endpoint telemetry. The retained investigation-time export contains PowerShell and command-shell process telemetry relevant to the investigated activity.

Microsoft Sentinel separately received endpoint telemetry through the configured Microsoft security integration. KQL was executed in the actual Sentinel workspace against `DeviceProcessEvents`.

Defender Advanced Hunting and Microsoft Sentinel KQL are separate evidence boundaries and are not treated as the same execution or result source.

## Evidence assessment

The observed activity was reconciled with the authorized Microsoft Defender for Endpoint detection-test scenario on the disposable laboratory endpoint.

The evidence reviewed in this investigation did not establish an unauthorized compromise.

The final analyst severity was therefore reduced from the initial `Medium` assessment to `Informational`, reflecting benign authorized test activity.

The historical Microsoft/vendor severity remains `Medium` and is not overwritten by the analyst assessment.

## Decision and closure

No material uncertainty remained that required Tier 2 escalation within the defined laboratory scope.

The incident was resolved after analyst documentation was recorded in Microsoft Defender XDR.

The incident interface subsequently displayed the resolved classification as `False alert`.

The retained XDR activity export separately records determination `Not malicious` and classification `False positive`. These values are preserved as platform-generated terminology and are not treated as interchangeable raw values.

No containment action was required for the authorized laboratory activity.

## Chronology boundary

The formal platform-event chronology is retained in `timeline.csv`.

The recorded timestamps establish alert association, assignment, status transitions, analyst documentation, platform classification and resolution events. They do not establish exact start or completion times for every analytical action performed between those recorded events.

Separate timestamped Sentinel and Defender Advanced Hunting executions performed after incident resolution are retained as post-closure evidence validation. They must not be interpreted as pre-closure investigative actions.

## Evidence boundaries

- Raw Defender and Sentinel CSV exports remain private.
- Unnecessary tenant, subscription, workspace, device and user identifiers are excluded or sanitized from public artifacts.
- Analyst-authored documentation is distinct from platform-generated evidence.
- Absence of malicious activity in the reviewed evidence does not prove absence of malicious activity outside the investigated scope.
