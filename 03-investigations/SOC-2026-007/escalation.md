# SOC-2026-007 — Tier 2 Escalation

## Case

Case ID: SOC-2026-007

Evidence state: SYNTHETIC / CONTROLLED LAB

Tier 1 severity: Medium

Classification: Suspicious phishing-like email

Decision: Escalate

## Why this case is being escalated

The retained message contains multiple suspicious characteristics:

- finance/payment pretext;
- urgency;
- visible author domain differing from reply and envelope domains;
- DMARC failure in retained scenario evidence;
- no DKIM result;
- embedded review URL.

Controlled enrichment cannot establish real-world reputation because the scenario intentionally uses reserved synthetic indicators.

## Material uncertainty

Tier 1 cannot determine from retained evidence:

- whether the recipient opened the message;
- whether the URL was clicked;
- whether credentials or payment information were submitted;
- whether additional recipients received related messages;
- whether endpoint activity followed delivery;
- whether identity compromise occurred;
- whether the sender was authorized to represent the visible author identity.

## Evidence requested from Tier 2

1. Message trace and mailbox-delivery scope.
2. Related-message search.
3. URL-click telemetry.
4. Proxy or secure-web-gateway evidence.
5. DNS evidence.
6. Identity sign-in evidence.
7. Endpoint telemetry.
8. Business validation of the sender/request.
9. Additional email-security platform context, if available.

## Evidence supplied

- retained synthetic `.eml`;
- mechanically derived metadata;
- IOC register;
- header and authentication analysis;
- user-impact assessment;
- controlled enrichment record;
- severity and disposition record.

## Containment status

No containment executed.

## Tier 1 handoff

Tier 1 assessment:

**Suspicious phishing-like email — Medium severity — material uncertainty remains — Tier 2 escalation required.**

No claim of confirmed compromise is made.
