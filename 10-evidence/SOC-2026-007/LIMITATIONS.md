# SOC-2026-007 — Limitations

## Evidence boundary

This case uses **SYNTHETIC / CONTROLLED LAB** evidence.

It is designed to demonstrate evidence handling, phishing triage, header analysis, authentication-result interpretation, indicator extraction, impact assessment, severity reasoning and escalation discipline.

## What the evidence does not establish

The retained evidence does not establish:

- production SOC experience;
- customer incident handling;
- production mailbox access;
- production mail-flow administration;
- Microsoft Defender for Office 365 runtime;
- successful credential harvesting;
- URL interaction by the recipient;
- endpoint execution;
- identity compromise;
- financial loss;
- broader delivery scope;
- malicious real-world infrastructure;
- executed containment.

## Authentication limitation

`Authentication-Results` is part of the synthetic message fixture.

SPF, DKIM and DMARC observations therefore describe retained scenario evidence.

They are not independently verified production DNS or mail-server authentication results.

## Reputation limitation

The URL and domains are synthetic reserved indicators.

Documentation address ranges are used for transport examples.

No real-world reputation conclusion can be derived from them.

No live URL request, VirusTotal lookup, URLhaus lookup, WHOIS/RDAP lookup, passive DNS query or commercial threat-intelligence lookup is claimed.

## User-impact limitation

User interaction remains UNKNOWN.

Absence of retained evidence for a click, credential submission, endpoint execution or financial impact does not prove that such activity did not occur outside the evidence scope.

## Scope limitation

Related-message delivery scope, sender authorization, identity telemetry and endpoint telemetry are unavailable in the retained evidence.

These gaps are the basis for Tier 2 escalation.

## Disposition limitation

The classification `Suspicious phishing-like email` is an analyst assessment.

It is not a claim of confirmed malicious infrastructure or confirmed compromise.

Final Tier 1 severity remains Medium and the case is escalated because material uncertainty remains.
