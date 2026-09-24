# SOC-2026-004 — registry Run key KQL runtime evidence

## Purpose

This directory retains reviewed runtime evidence for:

`04-detection-rules/kql/SOC-2026-004/registry-run-key-persistence.kql`

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

`da6e361c771c449cde5d9a5d18558fe8d7fb01225c1b38570e958ad042b3a9d6`

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

- UtcTime: `2026-09-23 09:02:30 UTC`
- RecordId: `SYS-007`
- Computer: `SYN-WIN-04`
- User: `SYNTH\ops.admin`
- ProcessGuid: `{c5871ac8-d6fd-52db-88e2-9ecd357ed841}`
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- TargetObject: `HKU\S-1-5-21-111111111-222222222-333333333-1104\Software\Microsoft\Windows\CurrentVersion\Run\LabUpdater`
- Details: `C:\Users\Public\lab-updater.exe`

The runtime result matched the previously documented synthetic-fixture
expectation.

## Evidence state

For `registry-run-key-persistence.kql`, this package supports:

- `KQL_WRITTEN`
- `KQL_TESTED`
- `KQL_EXECUTED`
- `KQL_RESULT_RETAINED`

## Boundaries

- The input is synthetic.
- The custom `Sysmon004` table is not a native Microsoft Sentinel table.
- Execution occurred in Azure Data Explorer / Kusto, not Microsoft Sentinel.
- No production telemetry was analyzed.
- The result demonstrates behavior only for the controlled fixture.
- A Run value records persistence configuration; it does not prove that the
  referenced executable existed or executed at a later logon.
- A Public or AppData path match does not establish effective file-system
  permissions for the relevant identity.
- The observed registry configuration does not by itself prove malicious
  intent or successful persistence.
- No production detection-efficacy, recall or false-positive-rate claim is made.
