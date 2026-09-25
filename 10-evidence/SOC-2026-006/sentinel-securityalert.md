# SOC-2026-006 — Sentinel SecurityAlert Correlation

## Evidence state

**RUNTIME_RESULT_RETAINED**

Microsoft Sentinel returned two `SecurityAlert` records associated with the investigated Microsoft Defender for Endpoint detection-test activity.

## Query execution

This retained result is from a post-closure evidence-validation execution. It must not be interpreted as a pre-closure investigative action.

- Platform: Microsoft Sentinel
- Query: `../../04-detection-rules/kql/SOC-2026-006/security-alert-execution-validation.kql`
- Execution timestamp: `2026-09-25 17:56:08.377 UTC`
- Query time range: previous 24 hours at execution time
- Result rows: 2
- Runtime result: `RUNTIME_RESULT_RETAINED`
- Query SHA-256: `013d4df32585dd0a4613ddab37966a5a69ccca99181d56f713150bc09fb598b5`
- Private raw-result SHA-256: `4a369f2a27db74b01edb20953ab8aadf598a271e6a366e94f56c878910487d47`
- Raw CSV: retained privately and excluded from the public repository

## Observed result
- Result rows: 2
- Alert 1: `Suspicious PowerShell command line`
- Alert 1 severity: `Medium`
- Alert 1 `TimeGenerated [UTC]`: `2026-09-25 17:15:52.301 UTC`
- Alert 2: `[Test Alert] Suspicious Powershell commandline`
- Alert 2 severity: `Informational`
- Alert 2 `TimeGenerated [UTC]`: `2026-09-25 17:15:26.567 UTC`
- Provider: `MDATP`
- Product: `Microsoft Defender Advanced Threat Protection`

The retained Sentinel result correlates the two Defender-generated alerts already reviewed as part of the SOC-2026-006 Microsoft XDR incident.

## Evidence integrity

The raw Microsoft Sentinel CSV export is retained privately. The public repository contains only reviewed, sanitized result metadata and the exact KQL used for this retained result.

## Boundaries
- This is authorized laboratory evidence, not production SOC experience.
- No tenant, subscription, workspace, user, device or alert identifier is published here.
- These two rows represent two alerts associated with the investigated laboratory activity; they must not be described as two separate investigated incidents.
- Microsoft Sentinel evidence and Defender Advanced Hunting evidence remain separate evidence boundaries.
