# SOC-2026-006 — Sentinel SecurityIncident Correlation

## Evidence state

**RUNTIME_RESULT_RETAINED**

Microsoft Sentinel returned four `SecurityIncident` records associated with the investigated Microsoft XDR incident.

## Query execution

This retained result is from a post-closure evidence-validation execution. It must not be interpreted as a pre-closure investigative action.

- Platform: Microsoft Sentinel
- Query: `../../04-detection-rules/kql/SOC-2026-006/security-incident-execution-validation.kql`
- Execution timestamp: `2026-09-25 18:06:35.483 UTC`
- Query time range: previous 24 hours at execution time
- Result rows: 4
- Runtime result: `RUNTIME_RESULT_RETAINED`
- Query SHA-256: `c0cf913facfa7fdc6b4ea33e26a0e7fc18c882a3d10c2e82606647cd670a2161`
- Private raw-result SHA-256: `2bbd100f872b1992cbc870bec07f7c0c2427e17c1f408528772a2a1f41b9fe30`
- Raw CSV: retained privately and excluded from the public repository

## Observed result

- Title: `Execution incident on one endpoint`
- Provider: `Microsoft XDR`
- Severity: `Medium`
- Result rows: 4
- Active rows: 3
- Closed rows: 1
- Earliest retained `TimeGenerated [UTC]`: `2026-09-25 17:05:58.895 UTC`
- Latest retained `TimeGenerated [UTC]`: `2026-09-25 17:12:19.132 UTC`

The retained sequence shows the incident represented in Microsoft Sentinel while active and subsequently represented as closed.

## Evidence integrity

The raw Microsoft Sentinel CSV export is retained privately. The public repository contains only reviewed, sanitized metadata and the exact KQL used for the retained result.

## Boundaries

- This is authorized laboratory evidence, not production SOC experience.
- No tenant, subscription, workspace, user or incident identifier is published here.
- The four rows are observations of the same incident title over time; they must not be described as four separate investigated incidents.
- This evidence establishes Sentinel-visible Microsoft XDR incident state for the retained query result.
