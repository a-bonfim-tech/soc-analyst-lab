# SOC-2026-002 KQL Runtime Evidence

## Purpose

This directory retains reviewed runtime evidence for the KQL query:

`04-detection-rules/kql/SOC-2026-002/repeated-failures-followed-by-success.kql`

The query was executed against the synthetic `SigninLogs` fixture in an
authorized Azure Data Explorer / Kusto environment.

This is evidence of KQL execution in Azure Data Explorer. It is **not**
evidence of Microsoft Sentinel execution or production-tenant activity.

## Evidence Chain

Input dataset:

`10-evidence/SOC-2026-002/signinlogs-synthetic.csv`

Query source:

`04-detection-rules/kql/SOC-2026-002/repeated-failures-followed-by-success.kql`

Runtime engine:

`Azure Data Explorer / Kusto`

Database:

`SOC2026002`

Source table:

`SigninLogs`

Source row count at validation:

`22`

Runtime-input verification:

`22/22 rows matched the versioned synthetic fixture after deterministic normalization`

Returned rows:

`1`

## Retained Artifacts

- `result.csv` — reviewed KQL query result.
- `execution-metadata.json` — engine, source paths, hashes, timestamps,
  SDK/Python versions and returned-column metadata.
- `source-schema.csv` — schema returned by `SigninLogs | getschema`.
- `source-validation.json` — retained source-table count and logical schema
  validation.
- `runtime-input-validation.json` — full normalized row-for-row comparison
  between the runtime `SigninLogs` table and the versioned synthetic fixture.

## Input Integrity

Dataset SHA-256:

`ab652d2c0de129f6e2fd231db69289af5f40880d528778a17f3d1eddb987738b`

Query SHA-256:

`8d07568f3fe1048c4a60baf54e9a5916c034ecae6e6a928ced12bc16cdc6308b`

## Result

The KQL engine returned one qualifying user/source pair:

- UserPrincipalName: `alex.meyer@contoso-lab.example`
- IPAddress: `203.0.113.77`
- FailureCount: `6`
- FirstFailure: `2026-09-21 20:31:02 UTC`
- LastFailure: `2026-09-21 20:32:33 UTC`
- SuccessTime: `2026-09-21 20:33:01 UTC`
- SuccessApp: `Azure Portal`

The runtime result matched the result previously derived from the synthetic
fixture and local regression model. A separate retained validation confirmed
that all 22 runtime `SigninLogs` rows matched the versioned fixture after
deterministic normalization.

## Evidence State

For this query, the retained package supports:

- `KQL_WRITTEN`
- `KQL_TESTED`
- `KQL_EXECUTED`
- `KQL_RESULT_RETAINED`

`KQL_TESTED` here refers specifically to execution in a named KQL engine with
retained input, output and comparison against the documented expected result.

No Microsoft Sentinel runtime claim is made.

## Limitations

- The dataset is synthetic.
- The execution occurred in Azure Data Explorer / Kusto, not Microsoft
  Sentinel.
- The result demonstrates query behavior for this controlled fixture only.
- It does not establish production detection efficacy.
- It does not prove credential compromise or malicious intent.
- No production identities, customer data or credentials are contained in
  this evidence package.
