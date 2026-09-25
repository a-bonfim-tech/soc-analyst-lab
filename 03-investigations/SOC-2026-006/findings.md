# SOC-2026-006 — Findings

## Findings

1. Microsoft Defender for Endpoint generated genuine PowerShell-related detections on the authorized disposable Windows laboratory endpoint.

2. Microsoft Defender XDR correlated the detections into an incident with vendor severity `Medium`.

3. Endpoint process evidence supported review of PowerShell and command-shell execution context.

4. Microsoft Defender Advanced Hunting returned relevant `DeviceProcessEvents` telemetry during the investigation.

5. Microsoft Sentinel separately provided visibility into ingested Microsoft security telemetry, and KQL was executed against `DeviceProcessEvents`.

6. The investigated activity was consistent with the authorized Microsoft Defender for Endpoint detection-test scenario.

7. No evidence reviewed within the defined investigation scope established an unauthorized compromise.

## Severity

- Microsoft/vendor severity: `Medium`
- Initial analyst triage severity: `Medium`
- Final analyst severity: `Informational`
- Final analyst context: benign authorized test activity

The final analyst assessment does not alter the historical vendor-assigned severity.

## Disposition

The incident was resolved without Tier 2 escalation or containment.

The resolved incident interface displayed `False alert`.

The retained XDR activity export records determination `Not malicious` and classification `False positive`. These platform observations are retained separately and are not normalized into a single raw platform value.

## Limitations

- This investigation covers only the retained evidence and defined authorized laboratory scope.
- Raw endpoint command lines, account information and unnecessary identifiers are not published.
- Some retained platform exports use localized timestamp representations.
- Post-closure validation queries do not establish that those specific executions occurred before incident resolution.
- No production SOC, customer incident, enterprise-scale monitoring or production response authority is claimed.

## Outcome

Within the reviewed evidence scope, the PowerShell-related detections were attributable to authorized laboratory test activity. The evidence supported resolution without escalation while preserving the original Microsoft severity, analyst severity progression, platform classification terminology and evidence boundaries.
