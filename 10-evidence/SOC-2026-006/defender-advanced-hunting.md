# SOC-2026-006 — Microsoft Defender Advanced Hunting Evidence

## Evidence state

**RUNTIME_RESULT_RETAINED**

Microsoft Defender Advanced Hunting was executed during the authorized SOC-2026-006 laboratory investigation against endpoint process telemetry.

This evidence is separate from the Microsoft Sentinel KQL execution documented elsewhere in this repository.

## Retained result

- Platform: Microsoft Defender XDR — Advanced Hunting
- Table: `DeviceProcessEvents`
- Result rows: 17
- Endpoint rows in retained export: 17
- `powershell.exe` rows: 13
- `cmd.exe` rows: 4
- Timestamp values present: 17

The retained export uses a localized timestamp representation. No UTC conversion is asserted here because the exported timestamp strings do not themselves establish a UTC offset.

## Post-closure execution validation

A separate Microsoft Defender Advanced Hunting query was executed after the incident had already been resolved. This execution provides a retained query-execution timestamp and must not be interpreted as a pre-closure investigative action.

- Platform: Microsoft Defender XDR — Advanced Hunting
- Table: `DeviceProcessEvents`
- Query: `../../04-detection-rules/kql/SOC-2026-006/defender-advanced-hunting-execution-validation.kql`
- Query behavior: latest 50 matching endpoint process records at execution time
- Result rows: 50
- Runtime result: `RUNTIME_RESULT_RETAINED`
- Retained `QueryExecutedAtUTC` value: `25 de set de 2026 20:59:38`
- Timestamp representation: localized as exported; no UTC offset is asserted from the CSV representation
- Query SHA-256: `571210db19614ccb8359b0bb3a923275485998811d9682e9e9f643543020b1df`
- Private raw-result SHA-256: `e24449fe372b63444c14bbe0bd2c01b8ba2112315e08ffe9f4a0af848508f1e3`
- Raw CSV: retained privately and excluded from the public repository

The validation result contains `QueryExecutedAtUTC` in the retained export. This validation does not change the historical incident timeline or imply that this query was executed before incident resolution.

## Retained fields

The private CSV export contains these fields:

- `Timestamp`
- `DeviceName`
- `AccountName`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `ProcessId`
- `InitiatingProcessId`

These fields supported review of process execution, command-line context and parent/initiating-process relationships during investigation.

## Investigation relevance

The retained Advanced Hunting result contains PowerShell and command-shell process telemetry from the authorized laboratory endpoint.

This telemetry was used as one evidence source during investigation of the PowerShell-related Defender alerts and associated Microsoft Defender XDR incident.

The result supports endpoint-process investigation. It does not, by itself, determine whether the activity was authorized, malicious or benign. Final disposition required correlation with the broader case context and retained evidence.

## Evidence integrity

The raw Advanced Hunting CSV export is retained privately and is intentionally excluded from the public repository.

The public repository retains reviewed metadata rather than raw endpoint command lines, account information or unnecessary identifiers.

## Boundaries

- This is Microsoft Defender Advanced Hunting evidence from an authorized laboratory environment.
- It must not be described as Microsoft Sentinel query output.
- Microsoft Sentinel KQL execution is documented separately.
- This evidence does not establish production SOC or customer-environment experience.
- Raw command lines, account information and unnecessary identifiers are not published.
