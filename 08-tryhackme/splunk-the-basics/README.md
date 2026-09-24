# TryHackMe — Splunk: The Basics

## Training state

**COMPLETED — GUIDED HANDS-ON TRAINING**

- Platform: TryHackMe
- Learning path: SOC Level 1
- Module: Core SOC Solutions
- Room: Splunk: The Basics
- Completion: 100%
- Environment: authorized TryHackMe Splunk laboratory
- Practical scope: Splunk navigation, data ingestion, indexing and SPL-based log analysis
- Portfolio relationship: SIEM and query preparation for SOC-2026-006

This record documents guided hands-on work performed inside the room-provided
Splunk laboratory.

It does **not** represent:

- professional SOC experience;
- production Splunk administration;
- operation of an employer or customer Splunk environment;
- enterprise-scale Splunk architecture design;
- production detection engineering;
- production incident response;
- administration of Splunk authentication, clustering or licensing;
- Microsoft Sentinel runtime evidence.

TryHackMe challenge answers, flags, credentials, copied room text and raw
challenge datasets are intentionally excluded.

## Practical lab execution

The room provided an authorized Splunk instance for hands-on work.

The guided practical exercise included:

1. accessing the laboratory Splunk instance;
2. navigating the Splunk interface;
3. opening the data-ingestion workflow;
4. uploading the room-provided VPN log dataset;
5. configuring the data as JSON events;
6. creating or selecting the `VPN_Logs` index;
7. completing ingestion;
8. opening Search & Reporting;
9. searching the indexed events;
10. filtering and aggregating structured fields to answer investigation
    questions.

This is therefore stronger evidence than theory-only training, while remaining
strictly a guided laboratory exercise.

## Splunk architecture

The room covered three core Splunk components.

### Forwarder

The Forwarder is the collection component positioned close to a data source or
endpoint.

Its role is to collect relevant telemetry or logs and forward that data toward
the Splunk platform.

### Indexer

The Indexer receives and processes ingested data.

For this portfolio, the relevant conceptual chain is:

`raw data → parsing → event representation → indexed searchable data`

### Search Head

The Search Head provides the analyst-facing search layer.

The laboratory used Splunk Search & Reporting to interact with indexed events
and perform searches using SPL.

## Data ingestion

The practical exercise used Splunk's Add Data workflow.

The retained ingestion sequence is:

`source → source type → input settings → index → review → ingestion`

The room-provided VPN dataset was newline-delimited JSON, allowing individual
JSON objects to be represented as separate events.

The practical index used during the exercise was:

`VPN_Logs`

## Dataset provenance

The raw room-provided dataset is **not committed to this repository**.

For reproducibility and provenance, the locally supplied training dataset was
independently parsed and recorded as:

- Logical JSON records: 2,862
- SHA-256:
  `33f9398b2394d7e2a70f91343a3319437490e2415435d057442a9516b72883a0`

This hash records which training dataset was examined without redistributing the
underlying challenge data.

The dataset contained structured fields relevant to log investigation,
including user identity, source IP, country, event time, connection action,
protocol and destination port.

No challenge-specific result values are retained here.

## SPL concepts practised

The room introduced practical use of Splunk Search Processing Language for
working with the ingested events.

Relevant operations included:

- scoping searches to an index;
- working with structured fields;
- JSON field extraction when required;
- filtering events by field value;
- excluding selected field values;
- counting matching events;
- aggregating values from matching events.

Representative SPL constructs encountered during the guided exercise included:

- `index=...`
- `search`
- `spath`
- `stats count`
- `stats values(...)`

These constructs are documented as training concepts rather than as evidence of
production Splunk query development.

## Analyst workflow retained from the exercise

The practical workflow can be summarized as:

`log source → ingestion → source typing → indexing → search → field extraction → filtering → aggregation → result validation`

From a SOC perspective, this is the beginning of the SIEM investigation chain:

`telemetry → indexed event → query → relevant event subset → analyst interpretation`

## Evidence boundary

The evidence supports:

- hands-on use of a Splunk instance in an authorized training environment;
- guided log ingestion;
- guided index creation/use;
- guided SPL querying;
- structured-field filtering;
- event counting and aggregation;
- familiarity with Splunk's principal architectural components.

The evidence does **not** support claims of:

- production Splunk experience;
- independent Splunk deployment;
- Splunk Enterprise administration in an organization;
- production correlation-search engineering;
- production alert triage in Splunk Enterprise Security;
- customer or employer incident investigation.

## Relationship to SOC-2026-006

This room contributes directly to preparation for SOC-2026-006 in:

- SIEM data-ingestion reasoning;
- indexed-event analysis;
- query construction;
- structured telemetry filtering;
- aggregation of investigation results;
- analyst interaction with a SIEM search interface.

It does **not** satisfy the SOC-2026-006 runtime requirements for:

- Defender for Endpoint onboarding;
- genuine Microsoft Defender alert generation;
- Defender XDR incident evidence;
- Microsoft Sentinel ingestion;
- Microsoft Sentinel KQL execution;
- retained Sentinel query output;
- analyst-authored laboratory ticket evidence;
- Microsoft-platform incident closure or escalation.

SOC-2026-006 therefore remains **PLANNED / PENDING EXECUTION**.

## Portfolio value

This exercise provides reproducible evidence of introductory hands-on SIEM work:
data was ingested into a laboratory Splunk instance, indexed and queried using
SPL-oriented workflows.

The evidence boundary remains explicit: this was authorized guided training,
not production SOC or production Splunk experience.
