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
false-positive rates. Separately, `unusual-admin-logon.kql` and `suspicious-powershell.kql` have retained
Azure Data Explorer / Kusto runtime evidence against their verified versioned synthetic inputs.

Timeline tests cover count/order, byte-for-byte regeneration, exact evidence retention,
correlation identities, host isolation, timezone normalization, shuffled input,
duplicate IDs, malformed input, CLI exit codes and source/output preservation.
The portfolio check validates required artifacts, Python syntax, structured data,
basic Markdown/link integrity and obvious sensitive-value patterns. This is a
heuristic leak check, not proof that arbitrary confidential data cannot be present.

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
registry-run-key-persistence SYS-007. The `unusual-admin-logon.kql` and
`suspicious-powershell.kql` expectations have been confirmed by retained Azure Data Explorer /
Kusto execution against verified synthetic inputs, producing `SEC-009` and `SYS-005`
respectively. The registry expectation remains a fixture-derived prediction, not a KQL runtime
result. Save actual query output and engine/schema details before upgrading the remaining
registry claim.

## CI

Existing Security & Quality Gate runs these unit and portfolio checks after the
existing Sigma validation. Older detection tests remain in place. CI success can
only be claimed after a GitHub run; local success alone is not a remote CI result.
