# SOC-2026-007 — Phishing / Email Investigation Scenario Contract

## Status

PLANNED / PENDING EXECUTION

## Purpose

Build a safe, reproducible Tier 1 phishing/email investigation from controlled evidence without representing synthetic or derived material as production telemetry.

## Evidence classification

Primary evidence state: SYNTHETIC / CONTROLLED LAB.

This case does not represent a production mailbox, customer incident, Microsoft Defender for Office 365 incident, or professional SOC engagement.

## Scenario

A laboratory user receives a suspicious email that requires Tier 1 analysis.

The analyst must determine what the retained email evidence supports, assess potential user impact, enrich relevant indicators, assign an evidence-bounded severity and disposition, and document either closure or escalation.

The final verdict must be derived from retained evidence. It must not be predetermined by this contract.

## Required lifecycle

Email evidence
→ alert / intake record
→ ownership
→ triage
→ header analysis
→ authentication analysis
→ indicator extraction
→ enrichment
→ user-impact assessment
→ severity reassessment
→ verdict
→ analyst notes
→ ticket
→ closure or escalation
→ documented evidence

## Required email evidence

The controlled message should retain, when applicable:

- sender;
- recipient alias;
- subject;
- message timestamp and timezone;
- Message-ID using a reserved laboratory domain;
- From;
- Reply-To;
- Return-Path;
- Received chain;
- Authentication-Results;
- SPF result;
- DKIM result;
- DMARC result;
- URLs;
- attachment metadata;
- attachment SHA-256 when an attachment exists.

## Safety requirements

All identities, domains and infrastructure created specifically for the scenario must be synthetic, controlled, sanitized, reserved for documentation, or otherwise explicitly authorized.

Do not use:

- real victim data;
- real credentials;
- active credential-harvesting infrastructure;
- malware;
- weaponized attachments;
- live malicious payloads;
- private authentication material;
- personal email addresses.

Any URL used solely as synthetic evidence must be non-actionable and must not direct a user to a credential collection or payload-delivery service.

## Analysis requirements

The analyst must review:

1. envelope/header relationships;
2. From versus Reply-To;
3. Return-Path;
4. Received chain;
5. SPF;
6. DKIM;
7. DMARC;
8. URL indicators;
9. attachment indicators when applicable;
10. domain/IP context when safely available;
11. user interaction state;
12. potential impact;
13. benign alternatives;
14. remaining unknowns.

## Evidence versus inference

Every material conclusion must distinguish:

- FACT — directly supported by retained evidence;
- DERIVED — mechanically calculated from retained evidence;
- ANALYST ASSESSMENT — reasoned interpretation;
- UNKNOWN — not established by available evidence.

Synthetic evidence must never be described as vendor-generated runtime evidence.

## Enrichment

Enrichment may use safe public sources or controlled local analysis.

For every enrichment result record:

- indicator;
- source;
- query or method;
- observation time;
- result;
- confidence;
- limitation.

Absence from a reputation source must not be treated as proof that an indicator is benign.

## Severity

Record separately:

- initial analyst severity;
- post-enrichment analyst severity;
- rationale;
- confidence.

Severity must reflect demonstrated scope and potential impact, not merely the presence of a suspicious indicator.

## Closure gate

Closure requires sufficient retained evidence to support the selected disposition and no material unresolved uncertainty requiring Tier 2 review.

The analyst must document:

- verdict;
- severity;
- user impact;
- evidence supporting the decision;
- benign alternatives considered;
- remaining limitations;
- recommended containment or follow-up, if any.

## Escalation gate

Escalate to Tier 2 if material uncertainty remains, including:

- evidence of credential submission;
- payload execution;
- malicious attachment behavior;
- confirmed malicious infrastructure requiring broader response;
- evidence of additional affected users or hosts;
- unresolved identity or authentication anomalies;
- insufficient evidence for a defensible Tier 1 disposition.

## Required artifacts

Before the case can be represented as completed, retain:

1. scenario contract;
2. sanitized email source;
3. email evidence metadata;
4. alert/intake record;
5. header analysis;
6. authentication analysis;
7. extracted IOC register;
8. enrichment record;
9. user-impact assessment;
10. investigation;
11. findings;
12. timeline;
13. analyst ticket;
14. severity assessment;
15. final verdict;
16. closure or escalation decision;
17. evidence manifest;
18. reproducibility instructions;
19. limitations;
20. repository validation for the exact candidate commit.

## Completion rule

This case remains PLANNED / PENDING EXECUTION until the required evidence has actually been generated, retained, reviewed and validated.

Successful creation of this contract alone is not evidence that the phishing investigation was executed.

## Public evidence boundary

Public artifacts must exclude unnecessary personal data, credentials, tokens, authentication secrets and sensitive internal identifiers.

Synthetic identities must be clearly recognizable as laboratory identities.

## Non-claims

This case does not independently demonstrate:

- production SOC employment;
- customer incident handling;
- production email-security administration;
- Microsoft Defender for Office 365 runtime;
- enterprise mail-flow administration;
- real-world victim interaction;
- malware detonation;
- production containment authority.
