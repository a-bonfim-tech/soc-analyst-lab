# SOC-2026-007 — Severity and Disposition

## Evidence state

SYNTHETIC / CONTROLLED LAB.

## Initial severity

Initial analyst severity: **Medium**

Rationale:

- finance/payment-themed social engineering;
- urgency designed to encourage action;
- visible author domain differs from reply and envelope domains;
- retained scenario records DMARC failure;
- no DKIM authentication result is present;
- one embedded review URL is present;
- recipient has a synthetic finance-role identity.

The initial severity represents triage priority before impact assessment and controlled enrichment.

## Post-enrichment severity

Final Tier 1 severity: **Medium**

Confidence: **Moderate**

The severity is not increased because retained evidence does not establish:

- URL interaction;
- credential submission;
- payload execution;
- endpoint compromise;
- identity compromise;
- financial loss;
- multiple affected recipients.

The severity is not reduced because the message retains multiple suspicious characteristics and user interaction remains unknown.

## Analytical classification

Classification:

**Suspicious phishing-like email**

This classification is evidence-bounded.

It does not assert that the synthetic sender infrastructure is malicious in the real world.

## Disposition

Disposition:

**Escalate to Tier 2 / email-security investigation**

Reason:

Tier 1 cannot defensibly close the case as benign because:

- user interaction is unknown;
- mailbox-wide scope is unknown;
- sender authorization is unknown;
- no click telemetry is available;
- no identity telemetry is available;
- no endpoint telemetry is available.

The escalation is based on unresolved material uncertainty, not on proof of compromise.

## Recommended Tier 2 collection

Request or review, where available:

1. mailbox/message-trace evidence;
2. delivery scope across recipients;
3. URL click telemetry;
4. secure-web-gateway or proxy telemetry;
5. DNS telemetry;
6. identity-provider sign-in telemetry;
7. endpoint telemetry for the recipient;
8. sender-domain authorization/business context;
9. related messages with matching sender, subject, URL or infrastructure.

## Containment

No containment action is represented as executed.

Potential containment decisions require additional evidence and organizational authority.

## Final Tier 1 decision

**ESCALATE**

The retained evidence supports a suspicious phishing-like message with unresolved user-impact and scope questions.

Tier 1 therefore preserves Medium severity and escalates for additional evidence rather than closing the case or asserting compromise.
