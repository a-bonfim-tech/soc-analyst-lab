# SOC-2026-003 — Windows Endpoint Tier 1 Investigation

## Scope and authorization

SOC-2026-003 is a controlled investigation performed in an authorized disposable
Windows laboratory. The endpoint activity was intentionally generated for telemetry
collection and analyst training.

This is real endpoint-generated telemetry, but it is not a production SOC incident,
customer environment or evidence of real compromise.

Raw endpoint exports remain private because they contain endpoint-specific
identifiers. This investigation references the sanitized derived evidence in
`10-evidence/SOC-2026-003/windows-endpoint-correlation.md`.

## Alert and source evidence

The investigation treats the controlled PowerShell execution as a laboratory
detection candidate requiring analyst review.

The behavior included:

- PowerShell process creation;
- use of `-EncodedCommand`;
- temporary Registry modification;
- temporary file creation;
- subsequent cleanup.

Individually, these behaviors can occur in both benign and malicious activity.
Their presence therefore requires contextual validation rather than an automatic
malicious verdict.

Evidence was collected from real Windows endpoint telemetry:

- Windows Security;
- Sysmon;
- PowerShell Operational.

The final collection normalized 541 source events and reported no missing required
sources after ingestion.

## Initial triage

Initial laboratory triage priority: **Medium**.

Rationale: encoded PowerShell plus Registry and file activity warrants review when
first observed without context. The initial priority represents the analyst's
starting position for the exercise, not a historical production alert severity.

Questions for triage:

1. Did independent telemetry sources record the same activity?
2. What command or script content is visible?
3. Does the Registry activity establish persistence?
4. Is the created file associated with harmful behavior?
5. Was the activity authorized?
6. Is there evidence of malware detection, unauthorized access, persistence,
   credential access, lateral movement or material impact?

## FACT / OBSERVATION

The retained derived evidence supports the following observations:

- Windows Security Event ID 4688 recorded PowerShell process creation.
- Sysmon Event ID 1 independently recorded corresponding PowerShell process
  creation.
- PowerShell Operational Event ID 4104 recorded the benign process marker.
- PowerShell Operational Event ID 4104 exposed the harmless payload associated
  with `-EncodedCommand`.
- Sysmon Event IDs 12 and 13 recorded temporary Registry activity.
- Sysmon Event ID 11 recorded creation of the temporary marker file.
- PowerShell Event ID 4103 recorded cleanup-related activity.
- The temporary Registry value was explicitly a lab marker and was not configured
  as persistence.
- The temporary Registry key and marker file were removed during cleanup.
- No Microsoft Defender Event IDs 1116/1117 were observed during the activity.
- The evidence package was transferred and SHA-256 verified before analysis.
- Baseline and final evidence integrity validation succeeded.

These statements are scoped to the collected evidence and do not imply production
detection or enterprise telemetry coverage.

## INFERENCE / alternatives

The encoded PowerShell invocation is potentially suspicious in isolation because
encoding can obscure command content. In this case, PowerShell telemetry exposed
the associated payload and the retained evidence identifies it as harmless lab
activity.

Registry modification can be associated with persistence techniques, but the
observed Registry value in this exercise was a temporary marker rather than an
autostart configuration.

File creation likewise does not establish malware execution. The observed file was
a temporary lab marker and was subsequently removed.

The correlated sequence is therefore consistent with the authorized controlled
activity used to generate telemetry.

Alternative explanations considered before closure include unauthorized PowerShell
execution, persistence configuration and malicious file creation. The retained
evidence does not support those conclusions.

## HYPOTHESES

### H1 — Malicious encoded PowerShell execution

Evidence that would increase confidence:

- malicious decoded/script-block content;
- unrecognized process ancestry;
- malicious file/hash evidence;
- Defender/EDR corroboration;
- unauthorized operator or execution context.

Observed evidence instead exposes a harmless lab payload.

Assessment: **not supported by retained evidence**.

### H2 — Registry-based persistence

Evidence that would increase confidence:

- autostart Registry location;
- persistence-oriented value;
- retained executable reference;
- subsequent execution attributable to the entry.

The observed value was explicitly a temporary marker and not an autostart
configuration.

Assessment: **not supported by retained evidence**.

### H3 — Authorized controlled laboratory activity

Supporting evidence:

- authorized disposable-lab scope;
- explicit SOC003 markers;
- known benign payload;
- temporal correlation across independent telemetry sources;
- temporary Registry/file artifacts;
- observed cleanup.

Assessment: **supported with high confidence within the lab scope**.

## UNKNOWN / NOT VERIFIED

The public evidence does not establish:

- enterprise EDR/XDR detection;
- Microsoft Sentinel execution;
- production SIEM alert creation;
- production user or asset impact;
- malicious intent;
- credential compromise;
- lateral movement;
- data theft;
- successful persistence;
- malware execution;
- complete channel history outside the bounded collection windows.

Absence of an event in the collection window is not proof that the underlying
capability or behavior cannot occur.

## Timeline and correlations

See [timeline.csv](timeline.csv) for the minimum sanitized analyst timeline and
[public correlation evidence](../../10-evidence/SOC-2026-003/windows-endpoint-correlation.md)
for the retained supporting observations.

The strongest correlation is the combination of:

1. Windows Security 4688 process creation;
2. Sysmon 1 corresponding process telemetry;
3. PowerShell 4103/4104 command and script context;
4. Sysmon 12/13 Registry activity;
5. Sysmon 11 file creation;
6. cleanup telemetry.

No single event is treated as proof of malicious activity.

## Severity before and after investigation

Initial laboratory triage priority: **Medium**.

Reason: encoded PowerShell combined with Registry and file activity warrants
contextual investigation when first encountered.

Post-investigation severity: **Low within this lab severity model**.

Reason:

- an authorized explanation is supported;
- decoded/script-block context is benign;
- Registry activity does not establish persistence;
- file activity is a temporary lab marker;
- cleanup is observed;
- no malicious impact is established.

This severity applies only to the portfolio laboratory model and is not an
enterprise incident rating.

## ATT&CK handling

PowerShell (T1059.001) is retained only as a behavioral reference for the
PowerShell execution observed in this benign laboratory exercise. It is not presented
as a confirmed adversarial technique.

Registry Run Keys / Startup Folder (T1547.001) is **not established** because the
observed Registry marker was not configured as an autostart mechanism.

ATT&CK references provide behavioral taxonomy; they do not establish malicious
intent or convert controlled laboratory activity into adversarial activity.

## Disposition

**Closed as authorized benign laboratory activity within the defined exercise.**

Confidence: **High** in the disposition within the retained lab evidence.

Closure is based on correlated evidence and the documented authorized activity,
not merely on the absence of Defender detections.

## Escalation decision

Tier 2 escalation is **not required for the completed laboratory scenario** because
the retained evidence supports the authorized benign explanation and no unresolved
material impact is established.

A Tier 2 escalation package is retained as a conditional decision artifact showing
which findings would have changed the disposition.

## Actions actually performed

- Windows telemetry collected from the authorized lab endpoint.
- Evidence package transferred to the analysis host.
- SHA-256 transfer integrity verified.
- Baseline and final evidence integrity validated.
- Final collection normalized.
- Relevant events correlated across multiple telemetry sources.
- Sanitized derived evidence prepared for public documentation.

No endpoint isolation, credential reset, process termination, malware remediation
or production containment was performed.

## Analyst summary

SOC-2026-003 demonstrates that suspicious-looking telemetry must be investigated in
context. Encoded PowerShell, Registry modification and file creation were observable,
but correlation with script content, explicit lab markers, authorization context and
cleanup supported a benign laboratory disposition.

The case therefore demonstrates both detection-oriented investigation and restraint:
behavior was investigated without converting suspicious indicators into unsupported
claims of compromise.
