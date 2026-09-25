# TryHackMe — Alert Triage With Splunk

## Training state

**COMPLETED — GUIDED HANDS-ON TRAINING**

- Platform: TryHackMe
- Learning path: SOC Level 1
- Module: SIEM Triage for SOC
- Room: Alert Triage With Splunk
- Completion: 100%
- Environment: authorized TryHackMe Splunk laboratory
- Practical scope: SIEM alert triage, SPL investigation, event correlation and escalation reasoning
- Portfolio relationship: practical SIEM-triage preparation for SOC-2026-006

This record documents guided hands-on investigation performed inside the
room-provided Splunk environment.

The exercise used pre-existing laboratory telemetry and guided scenarios. I
executed searches, filtered and correlated events, reconstructed activity
sequences and used the resulting evidence to support analyst decisions.

It does **not** represent:

- professional SOC employment;
- production SOC alert handling;
- operation of an employer or customer Splunk environment;
- production Splunk Enterprise Security experience;
- independent detection-rule engineering;
- production incident response;
- enterprise ITSM ticket handling;
- Microsoft Sentinel runtime evidence;
- Microsoft Defender runtime evidence;
- a real customer, employer or third-party incident.

TryHackMe flags, challenge answers, credentials, copied room text, screenshots
containing solutions and answer-key values are intentionally excluded.

## Practical lab execution

The room provided an authorized Splunk instance containing telemetry for three
guided investigation scenarios.

The practical workflow included:

1. scoping searches to the supplied investigation index;
2. identifying activity associated with an alert entity;
3. filtering relevant authentication, process and web events;
4. sorting events chronologically;
5. counting and aggregating matching events;
6. extracting fields when required;
7. correlating related records across an investigation;
8. distinguishing initial alert context from evidence discovered in the SIEM;
9. assessing whether the evidence supported malicious activity;
10. identifying when escalation beyond the L1 scope was appropriate.

This is hands-on SIEM investigation evidence in a controlled training
environment, not production SOC experience.

## Scenario 1 — Linux authentication investigation

The first scenario involved suspected initial-access activity against a Linux
host.

The investigation practised:

- scoping SSH authentication telemetry to a suspected source;
- differentiating invalid-user activity from valid-account authentication;
- distinguishing failed from successful authentication;
- counting authentication failures for a targeted account;
- determining the time span of repeated authentication attempts;
- identifying successful access following repeated failures;
- reviewing later privilege-related activity;
- identifying evidence of account creation as a persistence mechanism;
- reconstructing the activity in chronological order.

The analyst reasoning chain was:

`authentication anomaly → repeated failures → successful authentication → post-login activity → privilege change → persistence evidence → escalation`

The training reinforced that the number of raw events is not necessarily equal
to the number of authentication attempts. Related authentication mechanisms can
produce multiple records for one logical attempt, so the event type and message
semantics must be validated before counting.

## Scenario 2 — Windows scheduled-task persistence

The second scenario involved suspected persistence through a Windows scheduled
task.

The investigation combined Windows Security and Sysmon telemetry.

Relevant techniques practised included:

- reviewing scheduled-task creation events;
- examining task metadata and execution context;
- identifying suspicious command execution embedded in a task;
- correlating a task-creation event with process-creation telemetry;
- tracing process and parent-process identifiers;
- using process ancestry to reconstruct execution context;
- reviewing local-group discovery activity;
- correlating authentication activity with the subsequent user session;
- pivoting through Windows authentication records;
- using source-workstation information to enrich the investigation.

Windows event identifiers encountered during the guided investigation included:

- `4698` — scheduled task creation;
- `4624` — successful logon;
- `4776` — credential validation.

Sysmon process-creation telemetry was also used to connect process identifiers,
parent processes and command-line activity.

The retained analytical pattern is:

`alert → scheduled-task event → process correlation → parent process → discovery activity → authentication correlation → source context`

This demonstrates guided Windows-event correlation in Splunk. It does not
establish production Windows DFIR, enterprise threat hunting or independent
incident-response experience.

## Scenario 3 — Web-server and web-shell investigation

The final scenario involved suspicious activity against a web application and
possible web-shell interaction.

The investigation practised:

- filtering web requests by suspected source;
- reviewing HTTP paths, methods and response status;
- comparing activity by User-Agent;
- identifying automated credential-attack behavior;
- excluding one activity pattern to expose later suspicious requests;
- following referer information to correlate related web activity;
- identifying requests associated with a suspected server-side script;
- distinguishing normal navigation from repeated successful POST activity;
- validating that the activity supported escalation as malicious.

The retained workflow is:

`source IP → request volume → User-Agent analysis → authentication attack pattern → suspicious application path → web-shell-related activity → successful POST requests → escalation`

The exercise demonstrates web-log triage and correlation inside Splunk. It does
not prove how the server-side artifact was initially placed on the system when
the available logs do not contain that evidence.

## SPL techniques practised

The room extended the introductory Splunk work from the previous training
record into investigation-oriented searches.

Representative SPL operations practised included:

- index scoping with `index=...`;
- free-text and field-based filtering;
- Boolean search conditions;
- exclusion filters;
- chronological ordering with `sort`;
- result shaping with `table`;
- limiting result sets with `head`;
- field extraction with `rex`;
- event counting with `stats count`;
- grouping and aggregation with `stats`;
- calculating minimum and maximum event times;
- deriving investigation duration from `_time`;
- correlating identifiers and values across multiple searches.

These constructs are retained as guided laboratory experience, not production
Splunk detection engineering.

## Analyst workflow retained from the exercise

The room combined the alert-triage concepts from earlier training with direct
SIEM investigation.

The reusable workflow is:

`alert context → asset/user context → SIEM scope → relevant telemetry → timeline → correlation → enrichment → evidence assessment → verdict → escalation`

Several investigation principles were reinforced:

1. start with the alert context before querying;
2. do not treat the alert description as proof;
3. validate counts against the semantics of the underlying events;
4. correlate identities, hosts, process IDs, timestamps and network context;
5. distinguish what the logs prove from what remains unknown;
6. do not classify insufficient evidence as benign merely because a question
   remains unanswered;
7. escalate when evidence supports malicious activity beyond the L1 scope.

## Evidence boundary

The evidence supports:

- hands-on use of Splunk Search & Reporting in an authorized laboratory;
- guided SIEM alert investigation;
- SPL-based filtering and aggregation;
- Linux authentication-log analysis;
- Windows Security event analysis;
- Sysmon process-correlation practice;
- process and parent-process reasoning;
- Windows authentication-event correlation;
- web-access-log analysis;
- HTTP method, status, path and User-Agent analysis;
- event timeline reconstruction;
- evidence-based true-positive reasoning;
- L1 escalation reasoning.

The evidence does **not** support claims of:

- production Splunk experience;
- independent Splunk deployment or administration;
- Splunk Enterprise Security administration;
- production correlation-search development;
- production detection-rule engineering;
- production SOC alert ownership;
- production incident closure;
- production Windows DFIR;
- customer or employer incident investigation;
- independent malware or web-shell reverse engineering.

## Relationship to earlier TryHackMe training

This room builds directly on two earlier records.

`SOC L1 Alert Triage` provided the conceptual analyst lifecycle:

`alert → investigation → verdict → closure or escalation`

`Splunk: The Basics` provided the introductory SIEM workflow:

`telemetry → indexed event → query → relevant event subset → analyst interpretation`

This room combined those foundations into:

`alert → Splunk query → event correlation → timeline → evidence assessment → L1 decision → escalation`

## Relationship to SOC-2026-006

This room contributes directly to preparation for SOC-2026-006 in:

- SIEM alert-investigation workflow;
- query-driven triage;
- authentication analysis;
- event correlation;
- timeline reconstruction;
- process ancestry analysis;
- host and identity context;
- severity and verdict reasoning;
- escalation decisions;
- distinguishing evidence from unresolved questions.

It does **not** satisfy the SOC-2026-006 runtime requirements for:

- Defender for Endpoint onboarding;
- genuine Defender alert generation;
- Defender XDR incident evidence;
- Microsoft Sentinel ingestion;
- actual Microsoft Sentinel KQL execution;
- retained Sentinel query output;
- analyst-authored laboratory ticket evidence;
- Microsoft-platform incident closure or escalation.

SOC-2026-006 therefore remains **PLANNED / PENDING EXECUTION**.

## Portfolio value

This exercise provides hands-on evidence of guided SIEM triage beyond basic
log searching.

The portfolio value is the demonstrated investigation process:

`authentication → process → persistence → web activity → correlation → analyst decision`

The evidence boundary remains explicit: the work was completed in an authorized
TryHackMe Splunk laboratory using guided scenarios and synthetic/training
telemetry, not in a production SOC.
