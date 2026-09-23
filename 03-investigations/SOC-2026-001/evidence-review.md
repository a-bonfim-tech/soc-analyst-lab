# Retained evidence review — SOC-2026-001

Retrospective portfolio review. This supersedes unsupported execution details in the scenario narrative; it does not rewrite the original log.

Source: [real-lab-auth.txt](../../10-evidence/SOC-2026-001/real-lab-auth.txt), described by the repository as controlled real lab telemetry. The published copy is sanitized: internal addressing and the laboratory account name are replaced with TEST-NET-1 address `192.0.2.45` and account label `labuser`. Original acquisition metadata and a complete time-bounded export are absent; authenticity is not independently established.

| Retained observation | Source lines | Interpretation / limit |
|---|---|---|
| Eight `Failed password` records: admin 2, root 2, labuser 4 | 10,13,15,17,19,21,23,25 | Multiple failed attempts; no retained timestamps for these records, no five-minute rate established |
| One `Accepted password for labuser` from the same source | 27 | Successful authentication recorded; authorization and target inventory not established |
| Sudo-formatted entry naming USER=root and cat /etc/shadow | 30–31 | Sensitive command recorded; output, exit status and actual file disclosure unproven |

The excerpt does NOT establish 47 failures, the September 16 alert time, a 30-day baseline, inventory ownership, scheduled-test absence, failed sudo attempts, root session opening/closure or a complete host/session timeline. Those are scenario context in the original exercise, not independently retained observations.

## Timeline boundary

[Timeline](timeline.csv) preserves source order and the only partial timestamp. Most timestamps are UNKNOWN; `Sep 21 21:09:17` lacks year and timezone and cannot truthfully be normalized to UTC. Order in a collected excerpt does not prove causal linkage across every record.

## Retrospective triage

Initial scenario severity: Medium (recorded in the exercise). Current retained-evidence assessment: HIGH lab review priority because success and a sensitive privileged command record warrant investigation; confidence in maliciousness LOW, in the visible strings HIGH. This is not confirmed credential dumping or compromise. Authorization, command outcome and target criticality remain UNKNOWN.

Escalate to Tier 2 for original timestamped logs, sudo outcome/session context, asset identity, operator authorization and scope. Consider authorized testing, user errors or admin maintenance before malicious use. Do not assert source novelty without baseline data. Recommend evidence preservation and owner verification; no containment performed here.

## ATT&CK

- T1110.001: CANDIDATE; failures alone do not prove guessing intent.
- T1021.004: SSH mechanism OBSERVED in log strings; adversary lateral movement NOT VERIFIED.
- T1078: CANDIDATE; accepted account authentication does not prove abuse.
- T1548.003: CANDIDATE; sudo-style command record does not prove adversarial privilege escalation.
- T1003.008: CANDIDATE; command references /etc/shadow but successful dumping/disclosure is NOT VERIFIED.

Use [lab evidence/severity model](../../01-runbooks/evidence-and-severity.md).
