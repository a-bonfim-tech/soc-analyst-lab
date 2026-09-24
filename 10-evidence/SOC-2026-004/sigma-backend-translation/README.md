# SOC-2026-004 — Sigma backend translation evidence

## Purpose

This directory retains reviewed evidence from an explicit Sigma backend
translation exercise for the three SOC-2026-004 Sigma rules.

The translation environment used:

- `pySigma 1.5.1`
- `pysigma-backend-kusto 1.0.1`
- `KustoBackend`
- `microsoft_xdr_pipeline()`
- a disposable local Python virtual environment

This evidence is separate from the repository's existing parser-only validation
environment and does not change its dependency pin.

## Provenance

Source repository commit:

`6e01410cb651c833cb2b5a6dd3f34320ce55486f`

Translation Python version:

`3.14.7`

Evidence package recording time:

`2026-09-24T16:49:58Z`

The recording time above is the time this retained package received its
provenance metadata. The exact UTC timestamps of the earlier backend translation
and semantic-test executions were not captured contemporaneously and are
therefore intentionally recorded as unavailable rather than reconstructed.

The `generated_query_sha256` values identify the exact backend-emitted query
strings before the terminal newline used in the retained `.kql` files.
`retained_file_sha256` identifies the exact bytes of each retained `.kql` file.

## Evidence states

### Office-parent encoded PowerShell

Source:

`04-detection-rules/sigma/SOC-2026-004/suspicious-powershell.yml`

State:

- `BACKEND_TRANSLATED`
- `KUSTO_SEMANTIC_TEST_PASSED`

The backend produced one Microsoft XDR KQL query targeting
`DeviceProcessEvents`.

A read-only Azure Data Explorer / Kusto test using an inline `datatable`
returned only the intended positive case. The wrong-parent and
no-encoded-command controls did not match.

Generated query:

`suspicious-powershell.generated.kql`

### Registry Run value

Source:

`04-detection-rules/sigma/SOC-2026-004/registry-run-key-persistence.yml`

State:

- `BACKEND_TRANSLATED`
- `KUSTO_SEMANTIC_MISMATCH_CONFIRMED`

The backend produced one Microsoft XDR KQL query targeting
`DeviceRegistryEvents`.

The generated predicate contains:

`RegistryKey endswith "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*"`

A read-only Azure Data Explorer / Kusto semantic test established that the
tested realistic path ending in `...\Run\LabUpdater` did not satisfy this
predicate, while a synthetic control ending literally in `Run*` did.

The generated query is retained unchanged as evidence of the translation
result. The Sigma source rule is not modified merely to force backend
compatibility.

Generated query:

`registry-run-key-persistence.generated.kql`

### Remote privileged account outside approved sources

Source:

`04-detection-rules/sigma/SOC-2026-004/unusual-admin-logon.yml`

State:

- `BACKEND_TRANSLATION_BLOCKED_BY_ENRICHMENT`

Translation stopped with `SigmaTransformationError` because the Microsoft XDR
`DeviceLogonEvents` pipeline did not accept the enriched
`PrivilegedAccount` field.

The Sigma rule intentionally models explicit asset-context enrichment.
The separately authored SOC-2026-004 KQL implementation performs that context
operation through an asset-context join. The two artifacts are conceptually
aligned but are not interchangeable backend representations.

No generated backend query exists for this rule in this evidence package.

## Semantic test scope

The translated PowerShell and Registry queries were evaluated in an authorized
Azure Data Explorer / Kusto environment using only inline `print` and
`datatable` inputs.

The test:

- created no persistent table;
- ingested no data;
- dropped no table;
- used synthetic values only.

This semantic execution does not constitute Microsoft Defender XDR runtime,
Microsoft Sentinel runtime or production-tenant evidence.

## Boundaries

This package demonstrates backend translation behavior for the named versions
and pipeline only.

It does **not** establish:

- Microsoft Defender XDR execution;
- Microsoft Sentinel execution;
- production SOC activity;
- production telemetry analysis;
- broad detection efficacy;
- recall or false-positive rates;
- semantic equivalence between every Sigma rule and the separately authored
  SOC-2026-004 KQL rules.

The PowerShell backend output passed the limited retained semantic test.

The Registry backend output translated successfully at the software layer but
failed the retained intended-path semantic check.

The admin rule did not translate because its explicit enrichment fields are
outside the tested Microsoft XDR pipeline field contract.

## Retained artifacts

- `suspicious-powershell.generated.kql`
- `registry-run-key-persistence.generated.kql`
- `translation-metadata.json`
- `semantic-test-results.json`

Authentication prompts, device authorization values, tenant identifiers and
cluster endpoints are intentionally not retained.
