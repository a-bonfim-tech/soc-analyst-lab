# SOC-2026-004 — suspicious PowerShell KQL runtime evidence

## Purpose

This directory retains reviewed runtime evidence for:

`04-detection-rules/kql/SOC-2026-004/suspicious-powershell.kql`

The versioned query was executed unchanged in an authorized Azure Data
Explorer / Kusto environment against the synthetic `Sysmon004` table.

This is evidence of KQL execution in Azure Data Explorer / Kusto. It is
**not** evidence of Microsoft Sentinel execution or production-tenant
activity.

## Runtime input

Fixture:

`02-datasets/soc-2026-004/sysmon-events.json`

Fixture SHA-256:

`b61aaebb5f488531e6122ca05c3cb18a210d3b5ba5a554c49bafece5fff059c5`

Query SHA-256:

`2c3b70ba18cb458dd4f7b7fb4fabe0a701af20978294a4e85415cf6bda4d54a2`

Runtime validation:

- `Sysmon004`: 10/10 rows matched the versioned fixture after deterministic normalization.
- Empty fixture `DestinationPort` values were represented as null in the typed Kusto table.
- The `Sysmon004` runtime schema matched the documented KQL input contract.

## Retained artifacts

- `result.csv` — reviewed KQL result.
- `execution-metadata.json` — engine, source paths, hashes, timestamps,
  table count, SDK/Python versions and result metadata.
- `sysmon-schema.csv` — runtime schema returned for `Sysmon004`.
- `source-validation.json` — retained table count and logical schema.
- `runtime-input-validation.json` — retained fixture-to-runtime equality
  validation.

## Result

The KQL engine returned exactly one row:

- UtcTime: `2026-09-23 09:02:00 UTC`
- RecordId: `SYS-005`
- Computer: `SYN-WIN-04`
- User: `SYNTH\ops.admin`
- LogonId: `0x900`
- ProcessGuid: `{c5871ac8-d6fd-52db-88e2-9ecd357ed841}`
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- ParentImage: `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`

The retained command line contains the expected ` -EncodedCommand ` marker.
The runtime result matched the previously documented synthetic-fixture
expectation.

## Evidence state

For `suspicious-powershell.kql`, this package supports:

- `KQL_WRITTEN`
- `KQL_TESTED`
- `KQL_EXECUTED`
- `KQL_RESULT_RETAINED`

This package does not establish runtime evidence for
`registry-run-key-persistence.kql`.

## Boundaries

- The input is synthetic.
- The custom `Sysmon004` table is not a native Microsoft Sentinel table.
- Execution occurred in Azure Data Explorer / Kusto, not Microsoft Sentinel.
- No production telemetry was analyzed.
- The result demonstrates behavior only for the controlled fixture.
- Office ancestry plus encoded PowerShell does not prove malware, malicious
  document execution or malicious intent.
- Process-creation telemetry records the command line; it does not independently
  prove that every encoded statement completed successfully.
- No production detection-efficacy, recall or false-positive-rate claim is made.
