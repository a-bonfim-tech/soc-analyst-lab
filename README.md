# SOC Analyst Lab

<p align="center"><img src="assets/soc-analyst-lab-banner.png" alt="SOC Analyst Lab — practical security investigations" width="100%"></p>

Hands-on **SOC investigation portfolio** showing how I move from an alert or security signal to evidence correlation, timeline reconstruction, severity assessment, disposition and escalation.

**ALERT → INVESTIGATE → CORRELATE EVIDENCE → ASSESS SEVERITY → ESCALATE / CLOSE**

## See a complete investigation in 3 minutes

**[SOC-2026-003 — Windows endpoint investigation](03-investigations/SOC-2026-003/CASE_OVERVIEW.md)**

Real endpoint-generated Windows Security, Sysmon and PowerShell telemetry across **541 normalized source events**.

**Analyst path:** suspicious activity → multi-source correlation → encoded-PowerShell and Registry/file review → timeline reconstruction → severity reassessment → documented disposition.

[Investigation](03-investigations/SOC-2026-003/investigation.md) → [Evidence](10-evidence/SOC-2026-003/windows-endpoint-correlation.md) → [Timeline](03-investigations/SOC-2026-003/timeline.csv) → [Findings](03-investigations/SOC-2026-003/findings.md) → [Disposition](03-investigations/SOC-2026-003/escalation.md)

## Three cases to review

| Case | Evidence | Analyst work |
|---|---|---|
| **[SOC-2026-003 — Windows endpoint](03-investigations/SOC-2026-003/CASE_OVERVIEW.md)** | Real endpoint-generated Windows Security, Sysmon and PowerShell telemetry | Correlation, timeline reconstruction, PowerShell/Registry/file analysis, severity reassessment and disposition |
| **[SOC-2026-005 — Network traffic](03-investigations/SOC-2026-005/investigation.md)** | Real controlled-lab loopback PCAP with TShark and Zeek-derived telemetry | HTTP sequence reconstruction, timing analysis, file-transfer correlation, hypothesis testing and disposition |
| **[SOC-2026-001 — SSH authentication](03-investigations/SOC-2026-001/evidence-review.md)** | Retained controlled-lab Linux authentication excerpt | Failed/successful authentication correlation, privileged-command analysis and escalation reasoning |

## Demonstrated SOC workflow

- **Triage:** establish alert context, source, asset, account and time window.
- **Investigate:** preserve and correlate endpoint, authentication or network evidence.
- **Reconstruct:** build a bounded timeline and test alternative explanations.
- **Decide:** reassess severity and distinguish observations from hypotheses.
- **Act:** document disposition and escalate when the evidence warrants it.

## Additional technical depth

- **Detection engineering:** Sigma rules, KQL analysis, positive/negative controls and documented semantic limitations.
- **Windows investigation:** Security, Sysmon and PowerShell telemetry across host, process and time context.
- **Network analysis:** PCAP review with TShark and Zeek.
- **Authentication analysis:** failed/successful login correlation and privileged-command review.
- **Automation:** Python timeline normalization and bounded event correlation.
- **Engineering:** unit tests, repository validation and GitHub Actions quality gates.

[SOC-2026-004 — Sigma/KQL detection investigation](03-investigations/SOC-2026-004/investigation.md) · [SOC-2026-002 — identity correlation](03-investigations/SOC-2026-002/investigation.md) · [Detection evidence states](04-detection-rules/kql/README.md) · [Reproduction](REPRODUCE.md)

## Evidence boundary

This is an evidence-based training and laboratory portfolio. Results are bounded by the retained artifacts and must not be interpreted as production SOC employment or as proof of malicious activity beyond the evidence.

## Technical resources

[Runbooks](01-runbooks/README.md) · [Investigations](03-investigations/README.md) · [Detection rules](04-detection-rules/README.md) · [Automation](05-automation/build_timeline.py) · [Lab](07-lab/README.md) · [Evidence](10-evidence/README.md) · [Reproduction](REPRODUCE.md) · [Governance](00-governance/README.md)
