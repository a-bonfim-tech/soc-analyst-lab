# TryHackMe — SOC L1 Alert Triage

## Training state

**COMPLETED — GUIDED TRAINING**

- Platform: TryHackMe
- Learning path: SOC Level 1
- Module: SOC Team Internals
- Room: SOC L1 Alert Triage
- Completion: 100%
- Scope: guided SOC alert-triage training
- Portfolio relationship: preparatory training for SOC-2026-006

This record documents analyst concepts and workflow practiced in the room.

It does **not** represent:

- professional SOC experience;
- production alert handling;
- Microsoft Sentinel runtime execution;
- Microsoft Defender for Endpoint runtime evidence;
- Microsoft Defender XDR incident handling;
- enterprise ticket handling;
- an independently generated SOC-2026-006 alert;
- a real customer or employer incident.

TryHackMe flags, challenge answers, credentials, screenshots containing
challenge solutions, and copied room text are intentionally excluded.

## Skills practised

The room exercised the basic lifecycle followed by an L1 analyst when handling
security alerts.

### Event-to-alert reasoning

The training reinforced the distinction between:

1. an activity occurring on a system;
2. that activity being logged;
3. logs being collected by a security platform;
4. detection logic producing an alert;
5. an analyst reviewing the alert rather than manually reviewing every raw log.

The exercise covered the role of alert-management platforms such as SIEM, EDR,
NDR, SOAR and ITSM systems without establishing operational experience with any
specific commercial product.

### Alert properties

The analyst reviewed the main information normally required before triage:

- alert creation time;
- underlying event time;
- alert name;
- initial severity;
- status;
- verdict / classification;
- assignee / owner;
- alert description;
- affected entities and other alert-specific fields.

A platform-assigned severity is treated as an initial prioritisation signal, not
as an analyst conclusion about actual impact.

### Alert prioritisation

The training used a systematic queue-management approach:

1. exclude alerts already owned, resolved or under active investigation;
2. prioritize higher severity before lower severity;
3. for otherwise comparable alerts, review the oldest first.

The purpose is to make analyst selection reproducible rather than selecting an
alert based only on visual prominence or personal preference.

### Ownership and state transition

The practical workflow included:

1. selecting an eligible alert;
2. assigning ownership;
3. moving the alert to an in-progress state;
4. reviewing the alert details before investigation.

These state transitions are training-platform actions. They are not evidence of
enterprise ITSM, Sentinel or Defender incident handling.

### Investigation workflow

The room reinforced a Tier 1 investigation sequence:

1. identify the affected entity, such as a user or host;
2. identify the activity described by the alert;
3. review relevant activity around the alert time;
4. correlate surrounding events;
5. use available threat-intelligence or contextual resources where appropriate;
6. determine whether the observed activity is supported as malicious or benign;
7. document the reasoning.

The evidence should drive the verdict. Alert wording alone is not sufficient to
prove compromise.

### Verdict and closure

The training distinguished between:

- **True Positive** — the available evidence supports security-relevant
  activity requiring response or escalation;
- **False Positive** — the alert fired, but investigation supports a benign or
  otherwise non-threat explanation.

Insufficient evidence alone must not be treated as a False Positive. Within this
portfolio, unresolved evidence remains **Inconclusive**.

The exercise also practised documenting the reasoning and moving the alert to a
closed state after analysis.

A true-positive decision may require escalation to a higher-tier analyst
depending on the team's process. Closing or escalating a TryHackMe training
alert does not establish production incident-response experience.

## Analyst workflow retained from the exercise

The practical workflow can be summarized as:

`queue → eligibility → priority → ownership → in progress → alert context → surrounding events → enrichment → verdict → analyst comment → closure or escalation`

This sequence will be reused as a process reference for the later
SOC-2026-006 laboratory execution.

## Relationship to SOC-2026-006

SOC-2026-006 has a stricter evidence contract than this training room.

The TryHackMe exercise supports preparation in:

- alert queue reasoning;
- prioritisation;
- ownership;
- state management;
- initial investigation;
- surrounding-event review;
- enrichment;
- TP/FP reasoning;
- analyst commenting;
- closure / escalation concepts.

It does **not** satisfy the SOC-2026-006 runtime requirements for:

- Defender for Endpoint onboarding;
- genuine Defender alert generation;
- Defender XDR incident evidence;
- Microsoft Sentinel visibility;
- Sentinel KQL execution;
- retained Sentinel query output;
- analyst-authored laboratory ticket evidence;
- Microsoft-platform incident closure or escalation.

SOC-2026-006 therefore remains **PLANNED / PENDING EXECUTION**.

## Portfolio value

The room is retained because its workflow maps directly to entry-level SOC
responsibilities while remaining clearly separated from production and
vendor-runtime claims.

The value of this record is the documented analyst process, not possession of a
TryHackMe answer key or completion flag.
