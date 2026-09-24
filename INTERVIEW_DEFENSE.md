# Interview defense — evidence boundaries

## Contribution and provenance

Original scenario narratives and fixtures exist; this remediation corrects claims and adds retrospective review/templates. Personal mastery is not established by AI-assisted documentation.

SOC003 uses real endpoint-generated Windows lab telemetry with sanitized derived public evidence and private raw exports; SOC004 and SOC002 are synthetic; SOC001 uses a retained lab excerpt; DFIR notes are training-derived.

## What is supported

Supported evidence includes sanitized derived analysis of real endpoint-generated Windows lab telemetry for SOC-2026-003, synthetic-case reasoning for SOC-2026-002 and SOC-2026-004, restricted local detection tests, and the limited SOC-2026-001 Linux excerpt. Inspect [03-investigations/SOC-2026-003/investigation.md](03-investigations/SOC-2026-003/investigation.md), [03-investigations/SOC-2026-001/evidence-review.md](03-investigations/SOC-2026-001/evidence-review.md) and [REPRODUCE.md](REPRODUCE.md). Presence of a retained record is not independent proof of who performed every step.

## Execution, synthetic scope and changes

SOC-2026-003 has retained sanitized derived evidence from real endpoint-generated Windows Security, Sysmon and PowerShell Operational telemetry collected in an authorized disposable lab; raw endpoint exports remain private. SOC-2026-002 has retained Azure Data Explorer / Kusto output against a verified synthetic fixture. For SOC-2026-004, `unusual-admin-logon.kql`, `suspicious-powershell.kql` and `registry-run-key-persistence.kql` have retained Azure Data Explorer / Kusto output against verified synthetic inputs. The earlier Linux narrative exceeded its excerpt; that limitation was corrected, not concealed. Read the reproduction entry for current execution status. New documentation and proposed lab instructions are not newly executed evidence. Describe only work you personally understand and can reproduce; do not memorize AI-generated claims as personal experience.

## Conclusion and boundary

No production SOC work or public raw Windows evidence package is claimed. SOC-2026-003 documents an authorized disposable-lab collection using real endpoint-generated Windows Security, Sysmon and PowerShell Operational telemetry; the raw exports remain private and the public repository retains sanitized derived evidence. This is not a production incident, customer environment, Microsoft Sentinel execution or commercial SIEM/EDR experience. Retained KQL engine evidence covers SOC-2026-002 plus all three SOC-2026-004 KQL queries in Azure Data Explorer / Kusto against synthetic fixtures. The retained registry result establishes a controlled Run-value query match, not later autostart execution, effective ACLs or malicious intent. Containment recommendations are not actions taken. Do not invent failures, changes, actions, timestamps or runtime results.

## Five questions to defend from evidence

1. Why eight rather than 47 failed passwords? Compare the retained excerpt with the [SOC001 evidence review](03-investigations/SOC-2026-001/evidence-review.md); the larger count belongs to scenario prose.
2. Which timestamps are unknown? Inspect the [SOC001 timeline](03-investigations/SOC-2026-001/timeline.csv): do not invent the year or timezone absent from the retained lines.
3. Does a Run value prove persistence executed? Read the [SOC004 findings](03-investigations/SOC-2026-004/findings.md): configuration is suspicious but execution and malicious intent require further evidence; effective ACLs are also uncollected.
4. Why escalate, and what should Tier 2 resolve? Defend the rationale and open questions in the [SOC004 handoff](03-investigations/SOC-2026-004/escalation.md).
5. Why is pySigma parsing insufficient to claim an operational detection? Read the [validation guide](07-lab/detection-tests/SOC-2026-004/README.md): syntax/model checks remain distinct from backend translation, engine execution and production effectiveness. For SOC-2026-004, retained evidence now records KustoBackend/Microsoft XDR pipeline translation: PowerShell translated and passed a limited read-only ADX/Kusto semantic test; Registry translated but showed a confirmed semantic mismatch; the admin rule was blocked by its explicit enrichment field. None of this is Microsoft Defender XDR or Microsoft Sentinel runtime evidence.

If the artifact cannot support an answer, state UNKNOWN and identify the missing evidence.
