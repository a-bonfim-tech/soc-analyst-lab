# SOC-2026-007 — Phishing / Email Investigation

## Executive summary

A synthetic controlled-lab email targeting a finance-role laboratory recipient was investigated through a Tier 1 phishing workflow.

The retained message contains a payment-review pretext, urgency, an embedded review URL, differences between the visible author identity and reply/envelope identities, and retained scenario authentication results showing SPF pass for the envelope domain, no DKIM result and DMARC failure for the visible author domain.

The evidence does not establish user interaction, credential submission, endpoint execution, identity compromise, financial loss or broader recipient scope.

Final Tier 1 severity: **Medium**

Disposition: **Escalate to Tier 2 / email-security investigation**

No claim of confirmed compromise is made.

## Evidence state

Primary evidence: **SYNTHETIC / CONTROLLED LAB**

This case does not represent a production mailbox, production SOC incident or Microsoft Defender for Office 365 runtime.

## Alert / intake

Case ID: SOC-2026-007

Source: analyst-authored controlled phishing investigation fixture

Recipient role: synthetic finance-role user

Initial analyst severity: Medium

## Investigation performed

Tier 1 reviewed:

1. retained `.eml` evidence;
2. message metadata;
3. transport headers;
4. visible author, Reply-To and Return-Path relationships;
5. retained Authentication-Results;
6. URL indicators;
7. attachment state;
8. user-impact evidence;
9. controlled enrichment boundaries;
10. benign alternatives;
11. unresolved questions;
12. escalation requirements.

## Key findings

- The message uses a finance/payment-review pretext.
- The message requests immediate action.
- The visible author domain differs from the Reply-To and Return-Path domains.
- Two Received headers are retained.
- Retained scenario evidence records SPF pass for the envelope domain.
- Retained scenario evidence records no DKIM result.
- Retained scenario evidence records DMARC failure for the visible author domain.
- One synthetic reserved-domain URL is present.
- No attachment is present in the retained message.
- User interaction remains unknown.
- No real-world reputation is assigned to the reserved synthetic indicators.

## Hypotheses

### H1 — phishing / social-engineering attempt

Supported by multiple suspicious message characteristics.

This remains an analyst assessment and is not equivalent to proof of malicious infrastructure or successful compromise.

### H2 — legitimate but misconfigured or third-party mail flow

Not excluded by the retained evidence.

A legitimate workflow could potentially explain differences among visible author, reply and envelope identities or authentication anomalies.

Business authorization is not available in the retained evidence.

## User impact

UNKNOWN.

The retained evidence does not establish whether the recipient:

- opened the message;
- clicked the URL;
- submitted credentials;
- submitted payment information;
- downloaded content;
- triggered endpoint activity.

## Enrichment

The URL and domain intentionally use reserved synthetic infrastructure.

No live request was performed.

No external reputation result is claimed.

## Severity

Initial analyst severity: **Medium**

Final Tier 1 severity: **Medium**

The case is not raised because compromise is not established.

The case is not reduced because suspicious characteristics remain and material impact questions are unresolved.

## Decision

**ESCALATE**

Tier 1 cannot defensibly close the case as benign and cannot establish compromise from the retained evidence.

Additional mailbox, URL-click, identity, endpoint and delivery-scope evidence is required.

## Evidence boundaries

- Synthetic controlled-lab evidence only.
- Authentication-Results is retained scenario evidence, not independently validated production mail-server runtime.
- No production email-security administration is claimed.
- No real victim interaction is claimed.
- No malware execution is claimed.
- No containment action is represented as executed.
- UNKNOWN is preserved where evidence is unavailable.
