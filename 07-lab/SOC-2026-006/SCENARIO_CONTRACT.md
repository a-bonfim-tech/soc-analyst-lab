# SOC-2026-006 — SIEM/EDR alert lifecycle investigation scenario contract

## Evidence state

**PLANNED / PENDING EXECUTION**

This document defines the authorized laboratory scenario before any SOC-2026-006
formal runtime evidence is generated.

Its presence does not establish:

- Microsoft Defender for Endpoint onboarding;
- Microsoft Defender for Endpoint alert generation;
- Microsoft Defender XDR incident creation;
- Microsoft Sentinel ingestion;
- Microsoft Sentinel query execution;
- ticket handling;
- incident closure;
- Tier 2 escalation;
- production SOC experience.

Any of those states must remain **NOT VERIFIED** until supported by retained
runtime evidence.

## Objective

Demonstrate a bounded end-to-end SOC alert lifecycle using actual Microsoft
security platforms where technically and financially available.

The target operational chain is:

`endpoint telemetry → EDR detection → alert → XDR incident → SIEM visibility → KQL investigation → triage → enrichment → severity decision → lab ticket → closure or escalation → documented evidence`

The case is intended to address a portfolio gap between offline investigation
artifacts and the operational workflow used by Tier 1 / Junior SOC analysts.

The case must demonstrate evidence-backed handling of a real laboratory alert,
not merely screenshots of a configured product.

## Primary implementation

The intended primary environment is:

- disposable authorized Windows 11 ARM64 laboratory VM;
- Microsoft Defender for Endpoint;
- Microsoft Defender portal;
- Microsoft Defender XDR incident handling;
- Microsoft Sentinel workspace;
- Microsoft Sentinel connected to the Defender portal / Defender XDR incident
  integration;
- KQL executed in the actual Microsoft Sentinel environment;
- analyst-authored laboratory ticket record;
- repository evidence package containing reviewed derivatives only.

The existing laboratory endpoint may be reused only if its current state,
authorization and platform prerequisites are verified before execution.

No production endpoint, employer tenant, customer tenant, personal device used
for ordinary daily activity or third-party system may be used.

## Mandatory platform gate

The primary scenario may proceed only if a legitimate Microsoft Defender for
Endpoint evaluation/trial or other authorized lab entitlement is available.

Before any detection test:

1. the licensing state must be verified;
2. the Defender tenant must be controlled by the laboratory operator;
3. the Windows endpoint must be disposable and authorized;
4. onboarding must complete successfully;
5. the device must appear as onboarded/reporting in Defender;
6. Sentinel access must be verified;
7. the intended Defender XDR / Sentinel integration path must be verified.

If Defender for Endpoint cannot be legitimately enabled, SOC-2026-006 must
remain **PLANNED / PENDING EXECUTION** or explicitly record the failed platform
gate.

A local simulation must not be substituted and described as Microsoft Defender
for Endpoint runtime evidence.

## Architecture boundary

The target evidence path is:

1. Windows laboratory endpoint generates endpoint activity.
2. Microsoft Defender for Endpoint sensor reports endpoint telemetry.
3. Defender for Endpoint generates a real laboratory alert.
4. Microsoft Defender XDR creates or associates an incident.
5. The Defender XDR incident/alert becomes visible through Microsoft Sentinel.
6. The analyst executes KQL against the relevant Sentinel data.
7. Alert and incident context are enriched from available platform evidence.
8. The analyst records an initial and post-enrichment severity assessment.
9. A laboratory ticket records lifecycle state transitions and analyst actions.
10. The incident is closed or escalated according to retained evidence.

Every arrow above is a separate evidence boundary.

Failure of one step must not be silently inferred from successful execution of
another.

## Planned alert-generation method

The preferred signal-generation method is the Microsoft-documented Defender for
Endpoint EDR detection test executed only on the authorized disposable Windows
laboratory endpoint.

The purpose of the test is to verify genuine Defender for Endpoint sensor,
service and alert behavior without introducing real malware.

The formal command must be taken from the current Microsoft documentation at
execution time.

It must not be modified into a real payload, external command-and-control
sequence or unauthorized download.

The expected alert is not an observed alert until the Defender portal actually
records it.

## Initial analyst perspective

Initial triage must begin from the alert and incident evidence rather than from
the scenario's intended laboratory outcome.

The analyst may initially observe characteristics associated with suspicious
activity, such as:

- scripted PowerShell execution;
- download-and-execute-like behavior used by the official EDR verification
  sequence;
- EDR-generated alert metadata;
- affected device context;
- alert severity assigned by the Microsoft platform.

Those observations justify investigation.

They do not independently establish real malware execution, compromise,
unauthorized activity or production impact.

## Ground-truth handling

The operator knows that the scenario is an authorized laboratory exercise.

However, the investigation report must still establish the authorized
explanation from retained evidence.

The final disposition must not state "benign" merely because this scenario
contract exists.

Relevant supporting context should include, where available:

- laboratory endpoint identity;
- authorization record;
- execution window;
- documented Microsoft EDR test method;
- absence or presence of additional unexpected alerts;
- endpoint and incident context;
- analyst queries and retained results.

## SIEM investigation requirement

SOC-2026-006 must include actual Microsoft Sentinel query execution.

At minimum, the analyst should attempt to retrieve and correlate the relevant
alert and incident from Sentinel-supported data such as:

- `SecurityAlert`;
- `SecurityIncident`;

or their current supported equivalents if the service schema changes.

The exact tables and fields used must be recorded from the runtime environment.

Queries must not be described as executed in Sentinel unless they were executed
there.

For every retained KQL result, record:

- exact query text;
- query SHA-256 where practical;
- execution timestamp in UTC;
- workspace/environment identifier in sanitized form;
- query time range;
- result row count;
- reviewed result export;
- relevant field names;
- limitations;
- whether the result matched the expected alert/incident.

A KQL query that returns no rows is still a result and must not be rewritten to
force a match.

## EDR investigation requirement

The EDR portion should establish, where available:

- endpoint successfully onboarded;
- endpoint reporting state;
- Defender alert identifier in sanitized/public-safe form;
- alert creation time;
- product-reported severity;
- affected device;
- alert title/category;
- evidence or entities exposed by the platform;
- process or command-line context actually shown by the service;
- relationship between alert and incident;
- additional device context used during triage.

Advanced hunting, device timeline or other Defender features may be used only
when legitimately available.

Their absence must be documented rather than fabricated.

## Sentinel / Defender integration requirement

A Defender alert alone is insufficient for the intended SIEM/EDR case.

The investigation must retain evidence that the alert or associated Defender XDR
incident became visible through the Microsoft Sentinel operational path.

Required observations should include, where available:

- Sentinel-visible incident;
- associated alert count;
- incident severity;
- incident status;
- incident creation/update timestamps;
- product/source attribution;
- relevant entities;
- correlation between Defender and Sentinel identifiers.

Synchronization behavior must be described only from what is actually observed
in the lab.

## Analytics-rule boundary

A Microsoft Sentinel scheduled analytics rule is an optional extension, not a
prerequisite for the core EDR-to-SIEM lifecycle.

If a Sentinel-native analytics rule is added later:

- its query must be version controlled;
- execution must occur in Microsoft Sentinel;
- schedule and lookback must be recorded;
- threshold must be recorded;
- generated alert evidence must be retained;
- resulting incident behavior must be documented;
- duplicate incident generation must be considered.

A rule definition alone is not runtime evidence.

## Initial cost and ingestion boundary

The first implementation should enable only the data required to establish the
alert/incident lifecycle.

Do not enable broad Defender advanced-hunting event streaming or high-volume
raw-event ingestion merely to increase evidence volume.

Additional data ingestion requires an explicit later decision based on:

- expected cost;
- expected investigative value;
- retention requirements;
- privacy implications;
- cleanup requirements.

The case must prefer minimal sufficient telemetry over uncontrolled ingestion.

## Analytical hypotheses

### H1 — real unauthorized malicious endpoint activity

Potentially supporting evidence could include:

- unexpected or unauthorized execution;
- unrelated suspicious endpoint events;
- malicious artifact evidence;
- external malicious infrastructure;
- unexplained persistence;
- credential access;
- lateral movement;
- other corroborating alerts.

The planned Microsoft EDR verification sequence alone is not sufficient to
accept H1.

### H2 — authorized Defender for Endpoint laboratory detection test

Potentially supporting evidence includes:

- documented authorization;
- disposable lab endpoint;
- execution during the formal test window;
- Microsoft-documented detection-test behavior;
- alert timing corresponding to the controlled action;
- absence of unrelated malicious evidence;
- known lab ownership.

H2 is the planned ground truth but must still be supported by retained runtime
evidence before final closure.

### H3 — alert or incident unrelated to the planned test

This hypothesis must remain available if:

- timestamps do not correlate;
- device identity differs;
- additional alerts appear;
- platform evidence shows unrelated activity;
- expected test characteristics are absent.

Unexpected evidence must not be rewritten to fit H2.

## Severity model

Three different concepts must remain separate:

1. **Vendor alert severity** — severity assigned by Microsoft.
2. **Laboratory triage severity** — portfolio analyst assessment.
3. **Final laboratory severity** — analyst assessment after enrichment.

The Microsoft product's severity must not automatically become the analyst's
final severity.

Initial laboratory priority may be Medium if the EDR alert indicates suspicious
download/execution-like behavior and authorization has not yet been correlated.

The final severity must be derived from retained evidence.

No production incident severity is claimed.

## Ticket lifecycle requirement

SOC-2026-006 must create a real analyst-authored laboratory ticket record.

The ticket is not ServiceNow and must never be described as ServiceNow
experience.

The public ticket artifact should include:

- lab ticket ID;
- linked case;
- linked alert/incident identifiers in sanitized form;
- opened time;
- initial owner;
- status transitions;
- initial severity;
- enrichment performed;
- evidence references;
- analyst notes;
- final severity;
- final classification;
- closure or escalation rationale;
- closed/escalated time;
- unresolved questions.

Permitted lifecycle example:

`NEW → TRIAGE → INVESTIGATING → DECISION → CLOSED`

or:

`NEW → TRIAGE → INVESTIGATING → ESCALATED`

Actual transitions must be recorded when they occur.

Do not backfill fictional transition times after the exercise.

## Classification model

Final classification must use evidence.

Permitted case outcomes include:

- True Positive;
- False Positive;
- Benign Positive;
- Inconclusive.

For the planned authorized Microsoft EDR test, **Benign Positive** may become the
supported final classification if the evidence establishes that:

- the detection itself correctly identified the controlled behavior;
- the behavior was authorized;
- no unrelated malicious evidence is found.

The outcome must not be predetermined.

## Closure gate

Closure as Benign Positive requires:

1. correct affected device;
2. formal test window correlation;
3. documented authorization;
4. expected Microsoft test behavior;
5. no materially conflicting evidence;
6. query and incident review complete;
7. remaining uncertainty documented;
8. final severity rationale documented.

If those conditions are not satisfied, the case must not be closed merely to
match the exercise plan.

## Escalation gate

Escalate to Tier 2 within the laboratory model if material uncertainty remains,
including:

- alert cannot be tied to the authorized action;
- additional unexplained alerts exist;
- suspicious activity exists outside the formal test window;
- affected endpoint does not match the authorized lab endpoint;
- malicious artifact or external infrastructure is observed;
- identity or process context materially conflicts with the expected test;
- SIEM/EDR evidence is incomplete enough to prevent a defensible closure.

Tier 1 escalation is a recommendation/handoff, not authority to perform
containment.

## Containment boundary

The default scenario does not require containment.

Do not isolate the endpoint, disable an account, delete evidence, kill processes
or remove artifacts merely to simulate response activity.

Any real Defender response action must have:

- an explicit reason;
- an authorization boundary;
- a reversible or documented cleanup plan;
- retained runtime evidence.

Recommendations must remain distinct from actions actually performed.

## Required formal evidence

SOC-2026-006 is not complete until the retained evidence set supports, where
technically available:

1. lab environment metadata;
2. platform/license gate result;
3. endpoint onboarding evidence;
4. endpoint reporting evidence;
5. formal execution window;
6. Defender for Endpoint alert evidence;
7. Defender XDR incident evidence;
8. Microsoft Sentinel visibility evidence;
9. executed Sentinel KQL query;
10. retained Sentinel query result;
11. alert/incident correlation;
12. analyst triage record;
13. enrichment record;
14. initial and final severity;
15. laboratory ticket lifecycle;
16. final classification;
17. closure or Tier 2 escalation decision;
18. analyst timeline;
19. evidence manifest/hashes where applicable;
20. tool/platform/version metadata where exposed;
21. explicit limitations;
22. exact candidate-commit repository validation.

## Planned repository artifacts

The following structure is planned, but directories/files must be created only
when the corresponding evidence or analysis exists.

### Alert / operational record

`02-alerts/SOC-2026-006/`

Planned content:

- alert record;
- laboratory ticket record;
- sanitized alert/incident identifiers.

### Investigation

`03-investigations/SOC-2026-006/`

Planned content:

- `investigation.md`;
- `timeline.csv`;
- `findings.md`;
- `escalation.md` only if an actual escalation artifact is justified.

### KQL

`04-detection-rules/kql/SOC-2026-006/`

Planned content:

- Sentinel investigation queries actually executed;
- optional Sentinel-native analytics rule query if that extension is performed.

### Report

`09-reports/SOC-2026-006/`

Planned content:

- completed incident/lifecycle report derived from retained evidence.

### Runtime evidence

`10-evidence/SOC-2026-006/`

Planned content may include reviewed:

- environment metadata;
- sanitized onboarding state;
- Defender alert metadata;
- Defender XDR incident metadata;
- Sentinel incident/query results;
- query hashes;
- execution metadata;
- ticket lifecycle evidence;
- SHA-256 manifest.

No directory presence alone establishes execution.

## Public evidence boundary

Before publication, remove or transform sensitive values.

Do not publish:

- passwords;
- access tokens;
- cookies;
- API secrets;
- tenant IDs when unnecessary;
- subscription IDs;
- workspace IDs when unnecessary;
- device GUIDs when unnecessary;
- personal email addresses;
- signed URLs;
- session material;
- authentication headers;
- full account identifiers that are not required;
- unrelated tenant/device data.

Prefer stable sanitized aliases such as:

- `LAB-TENANT-006`;
- `LAB-ENDPOINT-006`;
- `LAB-ALERT-006`;
- `LAB-INCIDENT-006`;
- `LAB-TICKET-006`.

Raw screenshots should remain private unless each visible field has been reviewed
for publication safety.

Structured text/CSV/JSON derivatives are preferred because they permit precise
redaction and reproducibility.

## Provenance boundary

Platform-generated evidence and analyst-authored records must remain distinct.

Platform-generated evidence may include:

- Defender alert metadata;
- Defender incident metadata;
- Sentinel incident/query output;
- endpoint/device state.

Analyst-authored artifacts include:

- scenario contract;
- hypotheses;
- severity rationale;
- ticket notes;
- investigation;
- findings;
- handoff;
- final report.

Analyst-authored documentation is not proof that a platform action occurred.

## Evidence-state vocabulary

Use the repository governance vocabulary:

- **REAL CONTROLLED LAB**
- **SYNTHETIC**
- **TRAINING-DERIVED**
- **PLANNED / PENDING EXECUTION**
- **NOT VERIFIED**

Platform runtime evidence produced by the authorized lab may become
**REAL CONTROLLED LAB** after provenance and publication review.

## Explicit non-claims

SOC-2026-006 must not be represented as:

- employment in a production SOC;
- customer incident handling;
- enterprise-scale monitoring;
- 24x7 SOC operations;
- ServiceNow production experience;
- enterprise Microsoft Sentinel administration;
- enterprise Defender XDR administration;
- real attacker activity;
- real malware execution;
- production containment;
- production incident response authority;
- measured production false-positive rate;
- measured production detection efficacy.

The case demonstrates bounded laboratory use of real security platforms only to
the extent supported by retained evidence.

## Failure handling

A failed platform action is evidence and must be retained where safe.

Examples:

- trial unavailable;
- onboarding failure;
- endpoint not reporting;
- expected alert absent;
- Defender alert not correlated into an incident;
- Sentinel incident absent;
- KQL query returns no rows;
- integration permission failure;
- portal feature unavailable;
- unexpected schema/table behavior.

Do not silently replace failed execution with expected output.

Do not create synthetic artifacts that masquerade as the failed Microsoft
runtime step.

## Cleanup and trial boundary

Before deleting resources:

1. preserve required private originals;
2. create reviewed public derivatives;
3. record relevant hashes;
4. verify the case evidence package;
5. close or document the final incident state.

If a Defender for Endpoint trial is not being renewed, the laboratory endpoint
must be offboarded according to the supported Microsoft procedure before the
trial expires.

Azure/Microsoft resources created exclusively for the exercise should be
reviewed and removed after the required evidence is preserved, subject to
retention and billing requirements.

## Completion criteria

SOC-2026-006 may move from **PLANNED / PENDING EXECUTION** to a completed
**REAL CONTROLLED LAB** investigation only after all mandatory gates below are
satisfied:

1. authorized lab platform access verified;
2. disposable Windows endpoint successfully onboarded to Defender for Endpoint;
3. endpoint reporting confirmed;
4. formal EDR test executed in the authorized window;
5. genuine Defender for Endpoint alert retained;
6. associated Defender XDR incident retained;
7. Sentinel visibility of the alert/incident demonstrated;
8. actual Sentinel KQL executed and result retained;
9. analyst triage and enrichment documented;
10. initial and final severity documented separately from vendor severity;
11. laboratory ticket lifecycle recorded with real transition times;
12. final classification supported by evidence;
13. closure or Tier 2 escalation decision documented;
14. investigation timeline completed;
15. limitations and unknowns documented;
16. public/private evidence boundary reviewed;
17. evidence integrity validated where applicable;
18. repository validation passes for the exact final candidate commit.

If any mandatory gate is missing, the case must explicitly identify the
remaining gap rather than claiming full completion.
