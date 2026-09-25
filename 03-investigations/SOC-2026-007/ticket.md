# SOC-2026-007 — Analyst Ticket

## Case

- Case ID: SOC-2026-007
- Environment: Synthetic / controlled laboratory
- Detection source: Analyst-authored phishing investigation fixture
- Initial analyst severity: Medium
- Final Tier 1 severity: Medium
- Classification: Suspicious phishing-like email
- Final Tier 1 disposition: Escalate
- Containment: Not executed
- Confirmed compromise: Not established

## Lifecycle

| State | Evidence-backed analyst action |
|---|---|
| INTAKE | Retained synthetic email accepted as the primary investigation artifact. |
| TRIAGE | Sender, recipient, subject, transport headers, authentication fields, URL and attachment state reviewed. |
| INVESTIGATING | Header relationships, authentication observations, user impact, benign alternatives and controlled enrichment were assessed. |
| DECISION | Suspicious phishing-like email retained at Medium severity because suspicious characteristics remain while compromise is unconfirmed. |
| ESCALATED | Material uncertainty regarding user interaction, scope, identity and endpoint impact requires Tier 2 evidence collection. |

## Outstanding questions

- Was the message delivered to additional recipients?
- Did the recipient click the URL?
- Was any information submitted?
- Is the sender authorized to represent the visible author identity?
- Is there related identity or endpoint activity?
- Are related messages present elsewhere in the environment?

## Tier 2 evidence requested

- message trace and delivery scope;
- related-message search;
- URL-click telemetry;
- proxy or secure-web-gateway telemetry;
- DNS evidence;
- identity-provider sign-in telemetry;
- endpoint telemetry;
- sender/business authorization context.

## Evidence boundary

This ticket documents a synthetic controlled-lab investigation.

It does not claim production SOC employment, production email-security runtime, real victim interaction, confirmed compromise or executed containment.
