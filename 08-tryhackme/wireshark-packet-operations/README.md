# TryHackMe — Wireshark: Packet Operations

## Training state

**COMPLETED — GUIDED HANDS-ON TRAINING**

- Platform: TryHackMe
- Learning path: SOC Level 1
- Module: Network Traffic Analysis
- Room: Wireshark: Packet Operations
- Completion: 100%
- Environment: authorized TryHackMe Wireshark laboratory
- Practical scope: PCAP inspection, traffic statistics, protocol analysis, display filtering and packet-level validation
- Portfolio relationship: network-telemetry and packet-analysis preparation for SOC investigation

This record documents guided hands-on packet analysis performed inside the
room-provided Wireshark laboratory.

The exercise used pre-existing training traffic supplied by the platform. I
navigated Wireshark statistics, scoped packet populations, inspected protocol
metadata, constructed display filters and validated packet-level observations.

It does **not** represent:

- professional SOC employment;
- production network monitoring;
- packet capture from an employer or customer environment;
- independent acquisition of forensic network evidence;
- production NDR operation;
- enterprise packet-forensics experience;
- live incident response;
- malware command-and-control attribution;
- encrypted-session decryption;
- investigation of a real customer, employer or third-party incident.

TryHackMe flags, challenge answers, credentials, copied room text, screenshots
containing solutions, answer-key values and raw challenge packet captures are
intentionally excluded.

## Practical lab execution

The room provided an authorized Wireshark environment containing a packet
capture for guided analysis.

The practical workflow included:

1. opening and navigating the supplied packet capture;
2. reviewing capture-level summary information;
3. examining resolved addresses;
4. inspecting endpoint and conversation statistics;
5. analysing IPv4 destination and port statistics;
6. reviewing DNS service statistics;
7. reviewing HTTP request statistics;
8. constructing protocol and field-based display filters;
9. combining comparison and logical operators;
10. using advanced filter operators and field-conversion functions;
11. changing Wireshark configuration profiles;
12. validating TCP checksum status;
13. applying a preconfigured filtering button;
14. comparing filtered packet populations against the full capture.

This is hands-on packet-analysis evidence in a controlled training environment,
not production network-forensics experience.

## Wireshark statistics practised

The exercise used several Wireshark statistical views to reduce a large packet
capture into smaller analyst-relevant datasets.

### Resolved addresses

Resolved-address information was used to connect observed addresses with names
available in the capture context.

The analyst value is contextual enrichment:

`address → resolved name → additional investigation context`

A resolved name is treated as supporting context rather than proof that the
associated traffic is benign or malicious.

### Conversations

Conversation statistics were used to inspect communication relationships
between endpoints.

The retained analytical concept is:

`source ↔ destination → packet/byte volume → protocol context`

Conversation tables provide a fast way to identify prominent communication
pairs before deeper packet-level inspection.

### Endpoints

Endpoint statistics were used to review hosts observed in the packet capture
and compare their traffic characteristics.

Relevant analysis included:

- Ethernet endpoints;
- IPv4 endpoints;
- packet and byte volume;
- resolved names when available;
- manufacturer information derived from address metadata;
- geographical or autonomous-system context when exposed by the environment.

These metadata sources provide enrichment and scoping context. They do not by
themselves establish malicious activity.

### IPv4 destinations and ports

IPv4 destination and port statistics were used to identify heavily represented
destinations and understand how traffic was distributed across services.

The retained workflow is:

`capture → destination statistics → prominent destination/service → filtered packet review`

### DNS statistics

DNS service statistics were used to inspect query/response behaviour and timing.

The training reinforced that protocol statistics and packet counts must be
interpreted according to field semantics. A displayed statistical count is not
automatically equivalent to the number of logical client queries.

### HTTP statistics

HTTP request statistics were used to isolate and compare web traffic based on
request metadata.

This provided practice moving from aggregate protocol statistics into
packet-level HTTP inspection.

## Packet filtering

The room reinforced the distinction between **capture filters** and
**display filters**.

A capture filter restricts traffic before or during packet acquisition.

A display filter operates on packets already present in the capture and allows
the analyst to iteratively narrow the visible dataset without altering the
underlying capture.

The hands-on work used display-filter concepts including:

- protocol presence;
- field comparisons;
- source and destination ports;
- HTTP request properties;
- DNS fields;
- IP header fields;
- Boolean combinations;
- exclusion logic.

The investigation pattern retained is:

`full capture → hypothesis or question → display filter → reduced packet set → packet validation`

## Advanced filtering

The room introduced additional Wireshark filtering constructs used to make
packet selection more expressive.

### `contains`

The `contains` operator was used to reason about fields containing a particular
value or substring.

This is useful when an analyst needs to locate protocol metadata containing a
known textual element without requiring an exact full-field match.

### `matches`

The `matches` operator introduced regular-expression-based filtering.

The principal analytical value is flexible pattern matching across textual
protocol fields.

### `in`

Set membership with `in` was used to express a group of acceptable values in a
single filter rather than chaining multiple equality comparisons.

This is useful for protocol or port scoping where several related values belong
to the same investigation question.

### Field conversion

The exercise also introduced field-conversion functions such as converting
numeric values to strings before applying textual pattern matching.

This demonstrated that filter construction sometimes requires understanding
both a protocol field's underlying data type and the operator being applied.

## TCP checksum validation

The `Checksum Control` profile was used to expose TCP checksum validation
information in the packet view.

The exercise included:

1. switching from the default Wireshark profile;
2. identifying packets marked with a checksum problem;
3. inspecting the TCP checksum status field;
4. applying that field as a display filter;
5. validating the resulting packet population.

This provides guided experience using Wireshark packet metadata to isolate
checksum-related observations.

A checksum marked as bad is an observation requiring context. It is not, by
itself, proof of malicious traffic; checksum-offload behaviour, capture
conditions and other environmental factors can affect interpretation.

## Profiles and filtering buttons

The laboratory also demonstrated that Wireshark analysis can be influenced by
configuration profiles.

A profile may contain analyst-facing configuration such as:

- display preferences;
- protocol settings;
- colouring rules;
- saved filters;
- filtering buttons.

The exercise used an existing profile and a preconfigured filtering button to
scope traffic without manually reconstructing the underlying expression.

This reinforces the operational value of repeatable analyst tooling while
remaining a guided training exercise.

## Analyst workflow retained from the exercise

The reusable packet-analysis workflow is:

`PCAP → summary statistics → endpoint/conversation scoping → protocol statistics → display filtering → packet inspection → contextual interpretation`

Several investigation principles were reinforced:

1. start with aggregate statistics before manually inspecting thousands of packets;
2. reduce the dataset using a specific investigation question;
3. distinguish packet count from higher-level protocol semantics;
4. validate statistical observations at packet level;
5. use protocol fields rather than relying only on visual packet-list text;
6. combine filters incrementally to avoid hiding relevant evidence;
7. treat enrichment data as context rather than proof;
8. distinguish what the capture demonstrates from what remains unknown.

## Evidence boundary

The evidence supports:

- hands-on use of Wireshark in an authorized laboratory;
- navigation of a supplied packet capture;
- Wireshark summary-statistics analysis;
- endpoint analysis;
- conversation analysis;
- IPv4 destination and port analysis;
- DNS statistics review;
- HTTP request statistics review;
- construction of display filters;
- protocol and field-based filtering;
- Boolean and exclusion filtering;
- advanced operator use;
- regular-expression filtering concepts;
- set-membership filtering;
- field-conversion functions;
- TCP checksum-status inspection;
- Wireshark profile usage;
- filtering-button usage;
- packet-population validation.

The evidence does **not** support claims of:

- production packet capture;
- enterprise network-forensics ownership;
- production NDR administration;
- packet analysis for a real incident;
- independent PCAP acquisition;
- network sensor deployment;
- IDS/IPS administration;
- production threat hunting;
- malware traffic reverse engineering;
- encrypted-traffic decryption;
- customer or employer incident investigation.

## Relationship to earlier SOC training

Earlier TryHackMe records established complementary parts of the analyst
workflow.

`SOC L1 Alert Triage` established:

`alert → investigation → verdict → closure or escalation`

`Splunk: The Basics` established:

`telemetry → indexed event → query → relevant event subset → analyst interpretation`

`Alert Triage With Splunk` extended this into:

`alert → SIEM query → correlation → timeline → evidence assessment → escalation`

This Wireshark exercise adds packet-level network visibility:

`network traffic → packet capture → statistical scoping → protocol filtering → packet evidence → analyst interpretation`

Together, these exercises broaden the portfolio from alert and log analysis into
network-traffic analysis while preserving the distinction between guided
training and production experience.

## Relationship to SOC-2026-006

This room contributes to SOC-2026-006 preparation in:

- network-telemetry interpretation;
- source/destination reasoning;
- protocol-level investigation;
- packet-volume scoping;
- DNS context;
- HTTP context;
- filtering large telemetry sets;
- evidence reduction;
- contextual enrichment;
- evidence-versus-assumption discipline.

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

This exercise provides hands-on evidence that I can use Wireshark to move from a
large packet capture to a smaller, evidence-relevant packet population through
statistics, protocol context and display filtering.

Its portfolio value is the demonstrated analytical workflow:

`capture → scope → filter → inspect → validate → interpret`

The evidence boundary remains explicit: the work was completed in an authorized
TryHackMe laboratory using room-provided training traffic, not in a production
SOC or customer network.
