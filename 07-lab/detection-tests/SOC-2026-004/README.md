# SOC-2026-004 — reproduce and validate

Run from the repository root. Python 3.10+; timeline uses only standard library.
Tests reuse pySigma and its YAML dependency. An isolated environment is recommended:

```bash
python3 -m venv /tmp/soc004-validation
/tmp/soc004-validation/bin/python -m pip install pysigma==0.11.23
/tmp/soc004-validation/bin/python -m unittest discover -s tests -v
/tmp/soc004-validation/bin/python 06-scripts/validate_sigma.py
/tmp/soc004-validation/bin/python 06-scripts/validate_portfolio.py
python3 05-automation/build_timeline.py \
  --security-events 02-datasets/soc-2026-004/windows-security-events.csv \
  --sysmon 02-datasets/soc-2026-004/sysmon-events.json \
  --output /tmp/soc004-timeline.csv
cmp /tmp/soc004-timeline.csv 03-investigations/SOC-2026-004/timeline.csv
```

Expected: 23 rows, sorted UTC, with exact original evidence in JSON columns and
host/session/process correlations. Output is deterministic and atomic. Parent output
directory must exist. Invalid input or filesystem failure exits 2; success exits 0.
Source-overwrite is rejected. Input telemetry is never executed. CSV preserves raw
content for evidence fidelity; treat externally supplied CSV as untrusted when opening
in spreadsheets. This utility is scoped to these flattened fixtures, not raw EVTX.
The in-memory pairwise correlation is appropriate for 23 events, not a SIEM-scale job.

## Detection tests

Three rules should yield SYS-005, SEC-009 and SYS-007 respectively. Controls and
mutations exercise case handling, alternate paths, new source addresses, missing
context, other event IDs and near-match registry paths. Schema and pySigma parsing
validate rule structure. The narrow test evaluator accepts only one AND selection,
OR lists, equality, contains and endswith; unsupported conditions fail explicitly.
It is not a Sigma backend. This local detection-test utility does not itself execute KQL,
perform backend query translation or establish live ingestion, recall estimates or real-world
false-positive rates. Separately, `unusual-admin-logon.kql`, `suspicious-powershell.kql` and
`registry-run-key-persistence.kql` have retained Azure Data Explorer / Kusto runtime evidence
against their verified versioned synthetic inputs.

Timeline tests cover count/order, byte-for-byte regeneration, exact evidence retention,
correlation identities, host isolation, timezone normalization, shuffled input,
duplicate IDs, malformed input, CLI exit codes and source/output preservation.
The portfolio check validates required artifacts, Python syntax, structured data,
basic Markdown/link integrity and obvious sensitive-value patterns. This is a
heuristic leak check, not proof that arbitrary confidential data cannot be present.

## Sigma backend translation status

A separate retained exercise under
[`10-evidence/SOC-2026-004/sigma-backend-translation`](../../../10-evidence/SOC-2026-004/sigma-backend-translation/README.md)
executed `KustoBackend` with `microsoft_xdr_pipeline()` using pySigma 1.5.1 and
pysigma-backend-kusto 1.0.1. This is separate from the parser-only dependency
pin used by the repository validation suite.

Observed states:

- `suspicious-powershell.yml`: `BACKEND_TRANSLATED` and
  `KUSTO_SEMANTIC_TEST_PASSED`. The generated `DeviceProcessEvents` query
  returned only the intended positive case in the retained read-only
  Azure Data Explorer / Kusto inline-datatable test.
- `registry-run-key-persistence.yml`: `BACKEND_TRANSLATED` and
  `KUSTO_SEMANTIC_MISMATCH_CONFIRMED`. The generated
  `DeviceRegistryEvents` predicate used an `endswith` expression ending in
  literal `Run*`; the tested realistic `...\Run\LabUpdater` path did not
  match, while a literal-star control did.
- `unusual-admin-logon.yml`:
  `BACKEND_TRANSLATION_BLOCKED_BY_ENRICHMENT`. Translation stopped with
  `SigmaTransformationError` because `PrivilegedAccount` is an explicit
  enrichment field outside the tested Microsoft XDR `DeviceLogonEvents`
  field contract.

The source Sigma rules were not altered merely to force backend compatibility.
The semantic tests used synthetic inline values and created no persistent
tables, performed no ingestion and dropped no tables.

This evidence does not establish Microsoft Defender XDR execution, Microsoft
Sentinel execution, production telemetry analysis, broad detection efficacy,
recall or false-positive rates. The separately authored SOC-2026-004 KQL
queries retain their independent ADX/Kusto runtime evidence.

## Reproduce Sigma backend translation locally

Backend translation uses a separate dependency environment from the
parser-only validation suite:

```bash
python3 -m venv /tmp/soc004-sigma-backend
/tmp/soc004-sigma-backend/bin/python -m pip install \
  -r requirements-sigma-backend.txt
/tmp/soc004-sigma-backend/bin/python -B \
  06-scripts/validate_sigma_backend_translation.py
```

Expected translation-reproducibility states:

- `suspicious-powershell.yml`: retained Microsoft XDR backend query
  reproduced exactly;
- `registry-run-key-persistence.yml`: retained backend query reproduced
  exactly, including the already documented `Run*` semantic mismatch;
- `unusual-admin-logon.yml`: expected `SigmaTransformationError`
  reproduced with `PrivilegedAccount` as the blocking enrichment field.

The validator checks backend translation determinism against the retained
evidence package. It does not execute the generated KQL in Azure Data
Explorer / Kusto, Microsoft Defender XDR or Microsoft Sentinel. The retained
ADX/Kusto semantic-test evidence remains separate.

## KQL input contract and runtime status

Create your own sandbox tables before running the three queries:

- `Sysmon004`: fields from sysmon-events.json; EventID:int, UtcTime:datetime,
  DestinationPort:int (empty values mapped to null); all other fields:string.
- `Security004`: CSV fields; EventID/LogonType:int (empty LogonType to null),
  TimeGenerated:datetime; remaining fields:string.
- `AssetContext004`: hostname:string; privileged_accounts:dynamic array of strings;
  expected_admin_sources:dynamic array of strings. Exactly one row per hostname.

These custom table names are not native Microsoft Sentinel schemas. Normalize host,
account and address formats consistently. Ingest the fixtures explicitly; queries do
not fetch data or embed secret endpoints. Missing hosts are excluded by inner join;
track context completeness separately. Duplicated context rows would duplicate hits.

Expected results: suspicious-powershell SYS-005; unusual-admin-logon SEC-009;
registry-run-key-persistence SYS-007. All three expectations have been confirmed by retained
Azure Data Explorer / Kusto execution against verified synthetic inputs, producing `SYS-005`,
`SEC-009` and `SYS-007` respectively. The registry runtime result confirms the query matched
the controlled configuration event; it does not prove later persistence execution, effective
file-system permissions or malicious intent.

## CI

The Security & Quality Gate keeps the parser-only validation environment
separate from Sigma backend translation. Its backend-reproducibility step
creates an isolated virtual environment, installs
`requirements-sigma-backend.txt` and runs
`06-scripts/validate_sigma_backend_translation.py`.

Existing unit, portfolio, Windows collection and detection tests remain
separate. The CI backend step performs translation only; it does not connect
to or execute a KQL engine. CI success for a revision can only be claimed
after its matching GitHub Actions run completes successfully.
