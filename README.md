# SOC Analyst Lab

<p align="center"><img src="assets/soc-analyst-lab-banner.png" alt="SOC Analyst Lab — practical security investigations" width="100%"></p>

Evidence-first portfolio for an entry-level **SOC Analyst / Security Operations** role. It demonstrates bounded lab investigation, alert triage, timeline reconstruction, detection logic and written escalation. It does not establish professional production SOC experience.

## Start with the evidence

| Case | Evidence state | What can be inspected | Limits |
|---|---|---|---|
| [SOC-2026-004 — Windows investigation](03-investigations/SOC-2026-004/investigation.md) | SYNTHETIC | 23-event timeline; Windows Security/Sysmon-style fixtures; three Sigma rules; three KQL queries; severity and Tier 2 handoff | Local restricted evaluator and pySigma parsing; no Sigma backend or KQL runtime execution |
| [SOC-2026-001 — SSH authentication](03-investigations/SOC-2026-001/evidence-review.md) | REAL CONTROLLED LAB excerpt + scenario narrative | Eight failed passwords, one accepted login and a sudo command reference to `/etc/shadow` in the retained excerpt | Partial timestamps; scenario counts/baseline are not established by the excerpt; file contents and unauthorized access not proven |
| [SOC-2026-002 — identity correlation](03-investigations/SOC-2026-002/investigation.md) | SYNTHETIC | SigninLogs-style data, written KQL and local regression model | Reported ADX execution NOT VERIFIED: no retained runtime output; not Sentinel execution; compromise not confirmed |
| [SOC-2026-003 — real Windows endpoint telemetry](07-lab/WINDOWS_PENDING.md) | PLANNED | Collection and evidence acceptance gate | No remotely verifiable implementation or reviewed real Windows evidence package in this repository |
| [DFIR access and collection methodology](03-dfir/accessing-compromised-network.md) | TRAINING-DERIVED | Defensive collection reasoning, artifact selection and limitations | Reported training observations; not independently retained incident evidence or professional response experience |

## Review a case in five minutes

[SOC-2026-004 investigation](03-investigations/SOC-2026-004/investigation.md) → [evidence and provenance](02-datasets/soc-2026-004/README.md) → [timeline](03-investigations/SOC-2026-004/timeline.csv) → [findings](03-investigations/SOC-2026-004/findings.md) → [escalation](03-investigations/SOC-2026-004/escalation.md).

[Detection rules and ATT&CK limits](04-detection-rules/ATTACK-COVERAGE.md) · [KQL evidence states](04-detection-rules/kql/README.md) · [Reproduce locally](REPRODUCE.md) · [Interview defense](INTERVIEW_DEFENSE.md).

The workflow is **validate → collect context → correlate → test alternatives → assess severity → document → escalate or close**. An event, ATT&CK mapping, suspicious path or passing fixture test does not independently prove malicious intent, persistence execution or effective production detection. Effective ACLs must be checked before concluding that a particular public path is writable.

## What is implemented

- [Python timeline builder](05-automation/build_timeline.py): source preservation, UTC normalization and bounded host/session/process correlation.
- [Unit tests](tests/test_soc004.py) and [detection fixtures](07-lab/detection-tests/): positive and negative controls for documented local models.
- [Evidence and severity runbook](01-runbooks/evidence-and-severity.md), [triage procedure](01-runbooks/alert-triage.md) and [analyst templates](09-templates/README.md).
- [CI definition](.github/workflows/security-quality-gate.yml): parsing, tests, timeline and portfolio checks. A workflow file is configuration; check the matching commit's completed run before claiming remote success.

## Repository map

| Path | Contents |
|---|---|
| [00-governance](00-governance/README.md) | Scope, publication and evidence controls |
| [01-runbooks](01-runbooks/README.md) / [02-alerts](02-alerts/README.md) | Procedures / alert documentation area |
| [02-datasets](02-datasets/soc-2026-004/README.md) | Synthetic Windows fixtures |
| [03-investigations](03-investigations/README.md) / [03-dfir](03-dfir/key-artifacts-matrix.md) | Cases / collection methodology |
| [04-detection-rules](04-detection-rules/README.md) | Sigma, KQL and mapping limitations |
| [05-automation](05-automation/build_timeline.py) / [tests](tests/test_soc004.py) | Timeline implementation / unit assertions |
| [05-threat-intelligence](05-threat-intelligence/README.md) / [06-scripts](06-scripts/README.md) | Threat-intelligence area / validation utilities |
| [07-lab](07-lab/README.md) / [08-tryhackme](08-tryhackme/README.md) | Lab procedures / training boundaries |
| [09-reports](09-reports/README.md) / [09-templates](09-templates/README.md) | Reporting area / reusable analyst templates |
| [10-evidence](10-evidence/README.md) | Retained controlled-lab excerpt and synthetic identity data |

Directory presence alone does not mean a capability is demonstrated. Real Windows collection, live Sentinel/Defender/Entra investigations, phishing analysis and operational ticket handling remain evidence gaps until suitable artifacts are retained and reviewed.

## Evidence, reuse and assistance

Only reviewed synthetic, sanitized or explicitly approved artifacts belong here. Do not commit credentials, personal/customer information, raw sensitive captures, training flags or proprietary solutions. See [governance](00-governance/README.md) and [security reporting](SECURITY.md).

No open-source reuse license has been selected. Public visibility is not a blanket license to copy, modify or redistribute the material; third-party rights remain applicable. See the [reuse decision](00-governance/REUSE.md).

AI tools, including ChatGPT and Codex, may assist exercises, drafting and repository engineering. Claims remain bounded by retained artifacts; reviewed code and automated outputs still require the stated validation. AI assistance is not an independently demonstrated SOC capability.
