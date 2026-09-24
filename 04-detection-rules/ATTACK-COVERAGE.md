# SOC-2026-004 — evidence and detection coverage

Synthetic fixture behavior only; not broad ATT&CK coverage or production efficacy.

| Detection / behavior | Data source | ATT&CK scope | Sigma | KQL | Dataset records | Validated |
|---|---|---|---|---|---|---|
| Office-parent encoded PowerShell | Sysmon 1 | T1059.001 represented execution mechanism; intent unconfirmed | [Rule](sigma/SOC-2026-004/suspicious-powershell.yml) | [Query](kql/SOC-2026-004/suspicious-powershell.kql) | SYS-005 | pySigma parse + local selection regression + KustoBackend/Microsoft XDR pipeline translation + limited read-only ADX/Kusto semantic PASS + retained separately authored KQL `SYS-005` result |
| Remote privileged account outside baseline | Security 4624 + asset context; 4672 corroborates manually | T1078 candidate only; successful authentication is not proof of account abuse | [Rule](sigma/SOC-2026-004/unusual-admin-logon.yml) | [Query](kql/SOC-2026-004/unusual-admin-logon.kql) | SEC-009/010 | pySigma parse + local enriched selection regression + Microsoft XDR pipeline translation blocked by explicit enrichment + retained separately authored KQL `SEC-009` result |
| Run value referencing Public or AppData executable | Sysmon 13 | T1547.001 configuration; execution at next logon unproven | [Rule](sigma/SOC-2026-004/registry-run-key-persistence.yml) | [Query](kql/SOC-2026-004/registry-run-key-persistence.kql) | SYS-007 | pySigma parse + local selection regression + KustoBackend/Microsoft XDR pipeline translation + confirmed ADX/Kusto semantic mismatch in generated query + retained separately authored KQL `SYS-007` result |

[Dataset](../02-datasets/soc-2026-004/README.md) ·
[Investigation](../03-investigations/SOC-2026-004/investigation.md) ·
[Test procedure and limits](../07-lab/detection-tests/SOC-2026-004/README.md)

Python regressions read the actual YAML conditions through a deliberately restricted
evaluator; that evaluator is not a Sigma backend. Separately, retained
[Sigma backend translation evidence](../10-evidence/SOC-2026-004/sigma-backend-translation/README.md)
records execution of `KustoBackend` with `microsoft_xdr_pipeline()` using
pySigma 1.5.1 and pysigma-backend-kusto 1.0.1. The PowerShell rule translated
and passed a limited read-only Azure Data Explorer / Kusto semantic test. The
Registry rule translated but the generated query exhibited a confirmed semantic
mismatch for the intended realistic Run-value path. The admin rule translation
was blocked because its explicit `PrivilegedAccount` enrichment is outside the
tested Microsoft XDR `DeviceLogonEvents` field contract.

This is backend translation evidence, not Microsoft Defender XDR or Microsoft
Sentinel runtime evidence. Separately authored `unusual-admin-logon.kql`,
`suspicious-powershell.kql` and `registry-run-key-persistence.kql` retain Azure
Data Explorer / Kusto runtime evidence producing `SEC-009`, `SYS-005` and
`SYS-007` respectively against verified synthetic inputs. These measured fixture
results do not establish production efficacy or platform equivalence.
The admin Sigma rule requires PrivilegedAccount/SourceApproved enrichment; KQL joins
asset context instead. This is conceptual alignment, not proven platform equivalence.
Account and source arrays require canonical case/format; string predicates use
case-insensitive comparisons. Unknown hosts/sources must not silently become false
context facts. Empty source addresses do not qualify. Monitor missing enrichment
separately; absence of a match is not evidence of safety.

PowerShell detection deliberately misses abbreviation/quoting/obfuscation variants
outside ` -EncodedCommand ` or ` -enc `. Registry detection targets Run, not RunOnce,
and executable paths ending in .exe (optionally quoted), not arguments after .exe,
scripts, alternate hives or every autostart method. Expand only with fixtures/tests.

Network activity is not mapped to C2. Assigned privileges are not mapped to privilege
escalation. Automated timeline ATT&CK fields remain empty; analyst mappings live here.

The Public-directory match is a location heuristic, not proof of write permissions.
No effective ACLs were collected; verify them for the relevant identity and path.
AppData is generally user-writable in the owning user context, not necessarily by
other accounts. Neither path matching nor a Run value proves malicious intent or
execution at logon.
