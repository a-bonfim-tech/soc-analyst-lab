# SOC-2026-006 — Microsoft Sentinel KQL Runtime Evidence

## Execution state

**KQL_RESULT_RETAINED**

This directory documents KQL that was executed in an actual Microsoft Sentinel workspace during the authorized SOC-2026-006 laboratory investigation.

It is not a simulated, offline or Azure Data Explorer execution.

## Query

[`device-process-investigation.kql`](device-process-investigation.kql)

The query retrieves recent `DeviceProcessEvents` telemetry for the authorized disposable Windows laboratory endpoint and projects process-investigation fields used during triage.

## Retained result

- Platform: Microsoft Sentinel
- Table: `DeviceProcessEvents`
- Result rows: 18
- Result timestamp field: `Timestamp [UTC]`
- Earliest retained result: `2026-09-25 16:10:19.689 UTC`
- Latest retained result: `2026-09-25 16:22:57.045 UTC`
- Endpoint rows in retained export: 18
- `cmd.exe` rows: 1
- Controlled marker: `SOC-2026-006-SENTINEL-TEST`
- Rows containing controlled marker: 1
- `powershell.exe` rows in this specific Sentinel export: 0

The controlled marker was deliberately generated on the authorized laboratory endpoint to provide a bounded telemetry-correlation check. Its presence in the retained Sentinel result demonstrates that the corresponding endpoint process telemetry was ingested and retrievable through Microsoft Sentinel.

## Post-closure execution validation

A separate validation query was executed after the incident had already been resolved. This execution exists to retain an explicit UTC query-execution timestamp and must not be interpreted as a pre-closure investigative action.

- Query: `device-process-investigation-execution-validation.kql`
- Platform: Microsoft Sentinel
- Table: `DeviceProcessEvents`
- Execution timestamp: `2026-09-25 18:34:49.758 UTC`
- Explicit query time filter: none
- Query behavior: latest 50 matching endpoint records at execution time
- Result rows: 50
- Query SHA-256: `f4cd3d780ede97ce7427de24b463f41d350ce6818b3a61a7c5afbc4af9787c8f`
- Private raw-result SHA-256: `a1eab62ab2bc458f8197a2bedc6bc21944f2470ab941371fee1518ebde47a066`
- Raw CSV: retained privately and excluded from the public repository

This validation does not change the historical incident timeline or imply that the validation query was executed before incident resolution.

## Retained fields

The private CSV export contains these fields:

- `Timestamp [UTC]`
- `DeviceName`
- `AccountName`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`

## Evidence integrity

The raw Microsoft Sentinel CSV export is retained privately and is intentionally excluded from the public repository because it contains endpoint and command-line context that does not need to be publicly disclosed.

The public repository retains the query and reviewed metadata rather than the raw export.

## Boundaries

- This evidence demonstrates Microsoft Sentinel KQL execution and retained endpoint telemetry in an authorized laboratory environment.
- It does not establish production SOC or customer-environment experience.
- This Sentinel export must not be described as Defender Advanced Hunting output.
- Defender Advanced Hunting evidence is retained separately.
- The absence of `powershell.exe` rows from this specific export does not establish that PowerShell activity was absent from the broader investigation.
- No tenant, subscription or workspace identifier is required for the public evidence package.
