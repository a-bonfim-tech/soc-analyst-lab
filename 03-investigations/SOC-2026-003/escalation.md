# SOC-2026-003 — Conditional Tier 2 Escalation Decision

## Decision

**No Tier 2 escalation required for the completed laboratory scenario.**

The retained evidence supports authorized benign activity with high confidence
within the defined lab scope.

This document records the escalation boundary rather than representing a submitted
incident ticket.

## Evidence supporting closure

- Security 4688 and Sysmon 1 corroborate PowerShell process creation.
- PowerShell 4104 exposes the harmless controlled payload.
- Sysmon 12/13 records temporary Registry activity rather than demonstrated
  persistence.
- Sysmon 11 records creation of the temporary lab marker file.
- Cleanup activity is observed.
- The exercise was performed in an authorized disposable lab.
- No malicious impact is established.

## Conditions that would require escalation

Escalate for Tier 2 review if subsequent evidence establishes or leaves materially
unresolved:

1. execution without confirmed authorization;
2. malicious or unexplained decoded PowerShell content;
3. persistence-capable Registry configuration;
4. malicious executable or file evidence;
5. credential access or account compromise;
6. lateral movement or additional affected hosts;
7. material business or data impact;
8. contradictory telemetry that weakens the authorized explanation.

## Tier 2 questions if the disposition changes

- Who authorized the activity and what was the approved scope?
- What process ancestry and execution context produced the PowerShell activity?
- Is the decoded/script-block content expected?
- Did any Registry modification establish an autostart mechanism?
- Are created files known, signed and expected?
- Is related activity present outside the bounded collection window?
- Do identity, EDR, network or additional host sources corroborate unauthorized use?
- What containment is authorized and proportionate?

## Recommended evidence preservation if escalation becomes necessary

Preserve original Windows event exports and their integrity metadata, collect
additional relevant telemetry under approved authority, maintain original timestamps
and identifiers privately, and document all acquisition and containment actions.

Do not delete Registry/file artifacts or terminate processes solely to satisfy a
portfolio scenario.

## Actions actually performed

Evidence collection, transfer-integrity verification, ingestion, normalization,
correlation and analyst documentation were performed in the authorized lab.

No production escalation, endpoint isolation, credential reset or remediation was
performed.
