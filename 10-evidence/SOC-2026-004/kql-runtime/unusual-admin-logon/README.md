# SOC-2026-004 — unusual admin logon KQL runtime evidence

## Purpose

This directory retains reviewed runtime evidence for:

`04-detection-rules/kql/SOC-2026-004/unusual-admin-logon.kql`

The versioned query was executed unchanged in an authorized Azure Data
Explorer / Kusto environment against synthetic `Security004` and
`AssetContext004` tables.

This is evidence of KQL execution in Azure Data Explorer / Kusto. It is
**not** evidence of Microsoft Sentinel execution or production-tenant
activity.

## Runtime inputs

Security fixture:

`02-datasets/soc-2026-004/windows-security-events.csv`

Security fixture SHA-256:

`d93abd41d616b020acdd166fdb63f97da57983cb1408236b44d7ae5f7b32eed9`

Asset-context fixture:

`02-datasets/soc-2026-004/asset-context.json`

Asset-context fixture SHA-256:

`1314ae8e630dfce8532f13ab3fdd90aad059b9161bc71fc1fb5edc43caab51ba`

Query SHA-256:

`2d099dad5d32c11111660f9299911f7e32b096ecae943ccf849a9879a23b215b`

Runtime table validation:

- `Security004`: 13/13 rows matched the versioned fixture after deterministic normalization.
- `AssetContext004`: 1/1 row matched the query-relevant versioned context fields.
- `Security004` schema matched the documented KQL contract.
- `AssetContext004` schema matched the documented KQL contract.

## Retained artifacts

- `result.csv` — reviewed KQL result.
- `execution-metadata.json` — engine, source paths, source hashes, timestamps,
  table counts, SDK/Python versions and result-column metadata.
- `security-schema.csv` — schema returned for `Security004`.
- `asset-context-schema.csv` — schema returned for `AssetContext004`.
- `source-validation.json` — retained table counts and logical schemas.
- `runtime-input-validation.json` — retained fixture-to-runtime equality
  validation.

## Result

The KQL engine returned exactly one row:

- TimeGenerated: `2026-09-23 09:01:00 UTC`
- RecordId: `SEC-009`
- Computer: `SYN-WIN-04`
- Account: `SYNTH\ops.admin`
- IpAddress: `198.51.100.24`
- TargetLogonId: `0x900`
- LogonType: `10`

The runtime result matched the previously documented synthetic-fixture
expectation.

## Evidence state

For `unusual-admin-logon.kql`, this package supports:

- `KQL_WRITTEN`
- `KQL_TESTED`
- `KQL_EXECUTED`
- `KQL_RESULT_RETAINED`

The other SOC-2026-004 KQL queries are not covered by this package and must
retain their independent evidence states.

## Boundaries

- The inputs are synthetic.
- The custom tables are not native Microsoft Sentinel tables.
- Execution occurred in Azure Data Explorer / Kusto, not Microsoft Sentinel.
- No production telemetry was analyzed.
- The result demonstrates behavior only for the controlled fixture.
- An out-of-baseline privileged logon does not prove credential theft,
  malicious intent or account compromise.
- The inner join excludes hosts without matching asset context; context
  coverage must be assessed separately.
