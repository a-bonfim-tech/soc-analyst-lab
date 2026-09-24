# TryHackMe — Introduction to EDR

## Training state

**COMPLETED — GUIDED TRAINING**

- Platform: TryHackMe
- Learning path: SOC Level 1
- Module: Core SOC Solutions
- Room: Introduction to EDR
- Completion: 100%
- Scope: guided EDR fundamentals and simulated detection investigation
- Portfolio relationship: preparatory EDR training for SOC-2026-006

This record documents concepts and analyst workflow practised during the room.

It does **not** represent:

- professional SOC experience;
- production EDR operations;
- operational CrowdStrike Falcon experience;
- Microsoft Defender for Endpoint runtime execution;
- Microsoft Defender XDR incident handling;
- real endpoint containment or isolation;
- real process termination or file quarantine;
- production remote-response execution;
- a real customer or employer incident.

The practical investigation used a simulated EDR environment. Challenge answers,
flags, credentials, screenshots containing solutions, and copied room text are
intentionally excluded.

## Skills practised

### EDR purpose and analyst visibility

The room reinforced the role of Endpoint Detection and Response as an endpoint
security capability built around three broad functions:

- visibility into endpoint activity;
- detection of suspicious or malicious behaviour;
- response capabilities available to analysts.

The training emphasized that endpoint visibility gives analysts context around
detections rather than requiring decisions based only on an alert title or a
single indicator.

### Antivirus and EDR distinction

The room compared traditional antivirus concepts with EDR-oriented monitoring.

The principal distinction retained for this portfolio is that EDR analysis can
use behavioural context and endpoint telemetry across a sequence of actions,
including activity performed through otherwise legitimate processes.

This training does not establish operational experience with any particular
commercial EDR product.

### EDR architecture

The training covered the basic relationship between:

1. an endpoint agent or sensor;
2. telemetry collected from the endpoint;
3. a centralized EDR console;
4. correlation and detection logic;
5. alerts presented for analyst investigation.

The endpoint agent acts as the local collection component, while the central
platform correlates telemetry and provides investigation context.

### Endpoint telemetry

The room covered several telemetry categories relevant to SOC investigation:

- process execution and termination;
- parent-child process relationships;
- network connections;
- command-line activity;
- file and folder modifications;
- registry modifications.

The analyst value of this telemetry is correlation. Individual events may appear
benign in isolation but become significant when reconstructed as part of an
activity chain.

### Detection concepts

The training introduced multiple EDR detection approaches:

- behavioural detection;
- anomaly detection;
- IOC matching;
- MITRE ATT&CK mapping;
- machine-learning-assisted detection.

These mechanisms were studied as concepts used by EDR platforms. Their presence
in this training record does not establish independent implementation,
configuration or tuning of such mechanisms.

### Response concepts

The room introduced common EDR response capabilities, including:

- host isolation;
- process termination;
- file quarantine;
- remote endpoint access;
- artefact collection.

Examples of potentially collectible artefacts included endpoint logs, registry
data, filesystem content and memory-related evidence.

These capabilities were studied conceptually. The room did not provide evidence
that real production containment or response actions were executed.

## Simulated EDR investigation

The practical investigation used a simulated EDR dashboard containing multiple
detections.

The exercise required reviewing available detection context and correlating
information such as:

- process relationships;
- command execution;
- downloaded or suspicious files;
- network activity;
- endpoint identity;
- threat-intelligence context.

The goal was to extract relevant facts from EDR visibility and use them to
understand the activity represented by each detection.

The exercise did **not** include operational acknowledgement or response actions
against real endpoints.

No challenge-specific answers are retained in this repository.

## Analyst workflow retained from the exercise

The practical reasoning can be summarized as:

`detection → endpoint context → process relationships → telemetry review → network/file context → threat-intelligence context → analyst interpretation`

This extends the alert-triage workflow documented in the previous TryHackMe
exercise by adding endpoint-specific telemetry and EDR investigation concepts.

## Relationship to SOC-2026-006

This room supports preparation for SOC-2026-006 in the areas of:

- endpoint telemetry interpretation;
- EDR detection context;
- process-tree reasoning;
- behavioural detection concepts;
- IOC enrichment concepts;
- MITRE ATT&CK context;
- response-decision awareness;
- endpoint-focused investigation.

It does **not** satisfy the SOC-2026-006 runtime requirements for:

- Defender for Endpoint onboarding;
- genuine Microsoft Defender alert generation;
- Defender XDR incident evidence;
- real endpoint-response execution;
- Microsoft Sentinel visibility;
- Sentinel KQL execution;
- retained Sentinel query output;
- analyst-authored laboratory ticket evidence;
- Microsoft-platform incident closure or escalation.

SOC-2026-006 therefore remains **PLANNED / PENDING EXECUTION**.

## Portfolio value

This record demonstrates guided familiarity with the EDR investigation model and
the telemetry an entry-level SOC analyst uses to understand endpoint detections.

Its evidence boundary is intentionally narrower than production EDR experience:
the practical component was a simulated training investigation, not operation of
a production endpoint-security platform.
