# Evidence, lab severity and Tier 2 escalation

This is a portfolio LAB model, not an industry-wide standard or employer incident policy.

## Evidence vocabulary

- FACT: directly supported statement with source and scope.
- OBSERVATION: what a retained artifact records; authenticity and completeness still have limits.
- INFERENCE: reasoned interpretation, with alternatives and confidence.
- HYPOTHESIS: testable explanation and evidence that would falsify it.
- UNKNOWN: evidence missing.
- NOT VERIFIED: claim or reported execution without adequate retained proof.
- RECOMMENDATION: proposed action; never imply performed containment.

Preserve originals privately, hash them and record acquisition scope before deriving timelines. Hashes demonstrate integrity against a reference, not authenticity. Never convert a synthetic test into a real incident.

## Severity

| Level | Lab triage criteria | Response |
|---|---|---|
| LOW | Bounded low-impact observation; authorized explanation supported | Document evidence and closure basis; follow local review policy |
| MEDIUM | Suspicious anomaly; impact and authorization unresolved | Enrich identity, asset, history and related activity; escalate unresolved risk |
| HIGH | Correlated successful access plus sensitive privileged activity or suspicious persistence configuration | Prompt Tier 2 review; preserve evidence; request authorized containment decision |
| CRITICAL | Corroborated active destructive activity or widespread material impact on critical assets | Immediate incident lead notification under the lab exercise plan |

Consider asset criticality, privilege, confidence, successful access, credential/data access, persistence, lateral movement, scope, business impact and authorization uncertainty. UNKNOWN impact is not zero impact. A configured autostart is not proof it executed. Wazuh numeric rule level is not this case-severity scale.

For each case record initial severity, evidence added, post-review severity, rationale, confidence, escalation decision and Tier 2 questions. Never backfill a historical decision that was not recorded: label new assessments retrospective.

Before false-positive closure require an evidence-backed authorized explanation and scope check. One negative control is not a population false-positive rate. Follow employer authority limits; Tier 1 recommendation is not permission to isolate, disable or delete.
