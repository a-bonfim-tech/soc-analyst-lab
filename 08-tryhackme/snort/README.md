# TryHackMe — Snort

## Training state

**COMPLETED — GUIDED HANDS-ON TRAINING**

- Platform: TryHackMe
- Learning path: SOC Level 1
- Module: Network Security Monitoring
- Room: Snort
- Environment: authorized TryHackMe laboratory
- Primary technology: Snort 2
- Practical scope: IDS/IPS concepts, traffic sniffing, packet logging, alerting, PCAP investigation, configuration validation and rule fundamentals
- Portfolio relationship: guided network-security-monitoring and rule-based detection practice for SOC workflows

This record documents guided hands-on work completed in the room-provided
laboratory.

The training introduced Snort as a rule-based Network Intrusion Detection and
Prevention System and demonstrated how the same tool can be used for traffic
inspection, packet logging, alert generation, offline PCAP investigation and
rule-driven detection.

It does **not** represent:

- professional SOC employment;
- production IDS/IPS ownership;
- production inline packet blocking;
- enterprise Snort administration;
- production network monitoring;
- production firewall administration;
- independent forensic acquisition;
- customer incident-response ownership;
- production detection-engineering ownership;
- deployment of custom rules to a live enterprise network.

TryHackMe challenge answers, exercise-specific IP addresses, answer-key packet
values, exercise PCAP filenames, generated challenge log filenames, screenshots
containing solutions and raw challenge artifacts are intentionally excluded.

## Learning objectives

The room covers four principal areas:

1. IDS and IPS fundamentals;
2. Snort operating modes;
3. Snort traffic and PCAP analysis;
4. Snort rule structure and configuration concepts.

The practical objective is to understand how network traffic moves from packet
acquisition through decoding, preprocessing, rule evaluation and alerting.

## IDS and IPS fundamentals

The room distinguishes detection from prevention.

### Intrusion Detection System

An IDS monitors activity and generates alerts when suspicious or policy-relevant
conditions are identified.

The room introduces:

- Network Intrusion Detection Systems;
- Host-based Intrusion Detection Systems.

The operational model is:

`traffic → detection → alert → analyst review`

Detection itself does not automatically stop the activity.

### Intrusion Prevention System

An IPS actively protects traffic by taking preventive action when configured
conditions are detected.

The room introduces:

- Network Intrusion Prevention Systems;
- behaviour-based network prevention;
- wireless intrusion prevention;
- host-based intrusion prevention.

The operational model is:

`traffic → detection → prevention action`

The central distinction retained from the room is:

`IDS → detect and alert`

`IPS → detect and actively block or terminate`

## Detection and prevention techniques

The room introduces three broad approaches.

### Signature-based

Detection relies on known patterns represented by rules or signatures.

This is particularly effective for activity that already has a defined
recognisable pattern.

### Behaviour-based

Observed activity is compared with an established baseline of normal behaviour.

The room emphasises the importance of the baselining period because poor
training data can reduce detection quality and increase false positives.

### Policy-based

Observed activity is compared with defined configuration requirements or
security policies.

This can identify activity that violates organisational or technical policy even
when it is not inherently malicious.

## Snort capabilities

The room presents Snort as capable of:

- live traffic analysis;
- attack and probe detection;
- packet logging;
- protocol analysis;
- real-time alerting;
- rule-based detection;
- preprocessors;
- plugins and output integrations;
- offline PCAP analysis;
- IDS operation;
- IPS operation when configured inline.

These capabilities are used differently depending on the operating mode and
configuration.

## Snort operating modes

The room demonstrates several operational roles for Snort:

1. packet sniffer;
2. packet logger;
3. IDS/IPS engine;
4. PCAP investigation tool.

Each mode exposes different parts of the same packet-processing pipeline.

## Initial validation and configuration testing

Before analysing traffic, the room demonstrates confirming the Snort
installation and validating configuration.

Relevant commands include:

```text
snort -V
```

and:

```text
sudo snort -c /etc/snort/snort.conf -T
```

The important operational lesson is that configuration should be validated
before relying on the detection engine.

The principal parameters introduced are:

- `-V` / `--version` — display Snort version information;
- `-c` — specify a configuration file;
- `-T` — test the configuration;
- `-q` — suppress the default banner and startup information.

The room describes `snort.conf` as the central management file controlling
rules, preprocessors, detection behaviour and output settings.

## Sniffer mode

Snort can inspect live packets in a console-oriented packet-dump mode.

The room introduces:

- `-v` — verbose packet information;
- `-d` — packet payload data;
- `-e` — link-layer header information;
- `-X` — full packet details including hexadecimal output;
- `-i` — select the network interface.

These options can be combined.

Examples of the conceptual progression are:

```text
-v
→ packet metadata
```

```text
-vd
→ metadata + payload
```

```text
-de
→ payload + link-layer information
```

```text
-X
→ full packet-oriented hexadecimal view
```

The retained lesson is that the analyst should select only the amount of packet
detail required for the investigation.

## Packet Logger mode

The room demonstrates using Snort not only to display traffic but also to retain
captured packets.

The main logger-related options include:

- `-l` — choose the log/output directory;
- `-K ASCII` — write human-readable ASCII-oriented logs;
- `-r` — read previously generated binary packet logs;
- `-n` — limit how many packets are processed.

### Binary packet logging

Without ASCII mode, Snort can produce binary packet logs compatible with
packet-analysis workflows.

These logs can later be inspected using Snort or other packet-analysis tools.

The practical workflow is:

`live traffic → Snort logger → binary packet log → later investigation`

### ASCII packet logging

With `-K ASCII`, Snort creates human-readable, categorised output.

This makes it possible to inspect generated content directly using ordinary
text-processing tools.

The retained distinction is:

`binary logging → compact packet-oriented evidence requiring a compatible reader`

versus:

`ASCII logging → human-readable categorised evidence`

## Reading retained packet logs

The room demonstrates reopening binary Snort logs using `-r`.

Generic workflow:

```text
Snort packet log
→ snort -r
→ packet inspection
```

The same binary output can also participate in workflows using packet-analysis
tools such as tcpdump or Wireshark.

The room additionally demonstrates filtering retained packet data using
Berkeley Packet Filter expressions.

Examples of filter categories include:

- ICMP;
- TCP;
- UDP;
- specific ports;
- combinations of protocol and port.

This reinforces a transferable SOC skill:

`large packet set → filter → reduce scope → inspect relevant traffic`

## IDS/IPS mode

Snort's IDS/IPS operation is driven by configuration and rules.

Important parameters introduced in the room include:

- `-c` — load the configuration;
- `-T` — validate the configuration;
- `-N` — disable packet logging;
- `-D` — run in background/daemon mode;
- `-A` — choose alert output mode.

The room demonstrates that Snort can continue to perform detection even when
individual output or logging behaviours are changed.

## Alert modes

The room introduces several alert modes.

### Console

Provides compact alert information directly in the terminal.

Useful for interactive laboratory investigation.

### CMG

Provides alert context together with packet-header and payload information.

This gives more packet-level detail than console mode.

### Fast

Provides a concise alert representation containing core event information.

This is useful when an analyst needs compact alert output.

### Full

Provides more extensive alert information.

This mode is useful when more contextual detail is required.

### None

Disables alert generation while allowing other configured packet-processing
behaviour to continue.

The operational lesson is:

`alert format should match the investigation or operational requirement`

rather than assuming one output format is always appropriate.

## Background operation

The `-D` option runs Snort in daemon/background mode.

The room presents this primarily as an automation-oriented mode and warns that
it should be used only when configuration is stable and the operator
understands the environment.

This reinforces a general operational principle:

**validate interactively before automating persistent monitoring.**

## IDS versus inline IPS operation

The room explains that Snort normally operates passively for IDS use.

For inline prevention, the room introduces DAQ-based operation and the
`afpacket` approach.

Relevant concepts include:

- inline packet processing;
- DAQ selection;
- paired interfaces;
- drop/reject actions;
- configuration-driven prevention.

The retained distinction is:

`passive Snort → observe and alert`

versus:

`inline Snort → inspect and potentially block`

No production inline deployment was performed or claimed by this training
record.

## PCAP investigation mode

Snort can analyse stored packet captures instead of live network traffic.

The room introduces:

- `-r` / `--pcap-single` — process one capture;
- `--pcap-list` — process multiple captures;
- `--pcap-show` — display which capture is currently being processed.

The practical value is that the analyst can apply a ruleset to historical
traffic and use known detection patterns to accelerate investigation.

The retained workflow is:

`PCAP → Snort configuration → rule evaluation → alerts/statistics → analyst review`

## Single-PCAP analysis

When a single capture is loaded, Snort can provide traffic statistics and,
when rules are enabled, alerts generated from matching packets.

The practical lesson is that offline PCAP analysis becomes more useful when the
capture is evaluated with an appropriate ruleset rather than inspected only as
raw traffic.

## Multiple-PCAP analysis

The room demonstrates processing more than one capture in a single operation.

When many alerts are produced, source attribution can become difficult.

The `--pcap-show` option helps preserve which capture produced the currently
displayed results.

This reinforces an evidence-handling principle:

**retain source attribution while processing multiple evidence files.**

## Snort rule structure

The room introduces the basic Snort rule model as:

```text
action protocol source-address source-port direction destination-address destination-port (options)
```

A rule header identifies:

- action;
- protocol;
- source address;
- source port;
- traffic direction;
- destination address;
- destination port.

Rule options refine what the detection engine should inspect.

## Rule actions

The room introduces common actions including:

- `alert` — generate an alert and log the packet;
- `log` — log the packet;
- `drop` — block and log;
- `reject` — block, log and terminate the session.

The key lesson is that rule action controls what Snort does after a match.

A rule should therefore be tested carefully before any prevention-oriented
action is considered for a live environment.

## Protocol matching

The room explains that Snort 2 rules use four principal protocol identifiers:

- IP;
- TCP;
- UDP;
- ICMP.

Application-layer activity is then narrowed through ports and rule options.

This reinforces the distinction between:

`transport/network protocol selection`

and:

`application-pattern detection`

## Address and port matching

Rule headers can constrain traffic by:

- a single address;
- network ranges;
- multiple ranges;
- negated addresses;
- individual ports;
- port ranges;
- multiple ports.

Snort configuration variables can also be used to represent protected and
external networks.

The practical purpose is to narrow the rule's evaluation scope before more
expensive content inspection occurs.

## Traffic direction

The room introduces:

- `->` for source-to-destination matching;
- `<>` for bidirectional matching.

Direction is part of the rule header and should represent the traffic flow the
analyst intends to detect.

## General rule options

The room introduces general rule metadata such as:

- `msg` — human-readable alert message;
- `sid` — rule identifier;
- `reference` — external contextual reference;
- `rev` — rule revision.

The retained operational principles are:

- each local rule should have a unique identifier;
- revisions should be tracked;
- useful alert messages improve analyst interpretation;
- references can accelerate later investigation.

## Payload detection options

The room introduces payload-oriented matching.

### content

`content` searches packet payload data for a specified value.

Matches can use textual or hexadecimal representations.

### nocase

`nocase` removes case sensitivity from a content match.

### fast_pattern

`fast_pattern` allows a selected content value to be prioritised for initial
matching.

The broader lesson is that increasingly specific payload criteria can improve
detection precision but may also increase processing cost.

## Non-payload detection options

The room also introduces options that inspect packet metadata rather than
application payload.

Examples include:

- IP identification fields;
- TCP flags;
- payload size;
- same source/destination address conditions.

This demonstrates that rule-based detection does not depend solely on textual
payload signatures.

## Local rules

The room uses:

```text
/etc/snort/rules/local.rules
```

for user-created rules.

This separates analyst-created detections from broader rule collections and
supports controlled testing.

The retained development workflow is:

`write local rule → validate syntax → run against controlled traffic → inspect alerts → revise`

## Configuration variables

The room introduces several important `snort.conf` concepts.

### HOME_NET

Represents the network being protected.

### EXTERNAL_NET

Represents traffic considered external to the protected environment.

### RULE_PATH

Defines the primary rules directory.

### SO_RULE_PATH

Identifies a path associated with shared-object rules.

### PREPROC_RULE_PATH

Identifies a path associated with preprocessor/plugin rules.

These variables centralise scope and rule-path configuration.

## Data Acquisition modules

The room introduces DAQ as the packet-I/O abstraction used by Snort.

DAQ examples discussed include:

- PCAP;
- afpacket;
- IPQ;
- NFQ;
- IPFW;
- dump.

The two principal operational concepts emphasised are:

`PCAP → passive/sniffer-oriented processing`

and:

`afpacket → inline/IPS-oriented processing`

DAQ selection therefore affects how Snort receives and processes packets.

## Snort processing components

The room summarises Snort using several major components.

### Packet Decoder

Receives packets and prepares them for further processing.

### Preprocessors

Arrange, normalise or otherwise prepare packet data before rule evaluation.

### Detection Engine

Applies rules to packet data and determines whether configured conditions match.

### Logging and Alerting

Produces retained logs and analyst-facing alerts.

### Outputs and Plugins

Provide integrations and additional output or rule-processing capabilities.

The simplified processing model retained from the room is:

`packet acquisition`
`→ decoding`
`→ preprocessing`
`→ detection engine`
`→ logging/alerting`
`→ outputs`

## Rule sources

The room distinguishes three broad Snort rule sources:

- Community Rules;
- Registered Rules;
- Subscriber Rules.

The important operational lesson is that rulesets have different availability
and update models.

The room also cautions against replacing a configured `snort.conf` wholesale
when introducing or updating rules.

## Practical exercises

The hands-on work required applying Snort across multiple operational modes.

Without retaining challenge answers, the practical exercises included:

- validating Snort configuration;
- comparing configuration files;
- using multiple sniffer-mode parameter combinations;
- generating and reading packet logs;
- comparing binary and ASCII logging;
- filtering retained packet data;
- running IDS alert modes;
- examining alert output;
- analysing captured traffic with Snort rules;
- comparing results under different configurations;
- processing multiple PCAPs;
- creating local rules;
- matching packet metadata;
- matching TCP flags;
- matching payload content;
- working with rule revisions.

These exercises required moving between packet acquisition, configuration,
logging, detection and rule analysis rather than relying on a single Snort
feature.

## Investigation workflow retained from the room

A reusable Snort workflow is:

`validate configuration`
`→ acquire or load traffic`
`→ select operating mode`
`→ apply rules`
`→ collect alerts/logs`
`→ filter relevant evidence`
`→ inspect packet context`
`→ refine detection`
`→ retest`

For offline evidence:

`PCAP → ruleset → alerts/statistics → packet review → finding`

For rule development:

`hypothesis → local rule → syntax validation → controlled test → result review → revision`

## Operational practices reinforced by the room

The conclusion emphasises several practical habits:

1. understand fundamental rule structure before attempting complex rules;
2. add rule options incrementally so syntax problems are easier to identify;
3. reuse or improve an existing working rule where appropriate;
4. back up configuration files before making changes;
5. avoid deleting a working rule merely because it is temporarily unnecessary;
6. test newly created rules before considering production deployment.

These practices reduce the risk of configuration failure and uncontrolled rule
behaviour.

## Analyst lessons

The room reinforces several transferable SOC principles:

1. distinguish passive detection from active prevention;
2. validate configuration before trusting detection output;
3. choose packet-detail verbosity according to the investigative need;
4. preserve packet evidence when logging traffic;
5. understand the trade-off between binary and human-readable logs;
6. filter large traffic datasets before detailed inspection;
7. treat alert format as an operational choice;
8. preserve PCAP source attribution when processing multiple captures;
9. understand rule headers before adding complex options;
10. test local rules against controlled evidence before broader use;
11. maintain unique rule identifiers and revision history;
12. understand the packet-processing pipeline behind an alert.

## Evidence boundary

The evidence supports claims of:

- completed guided Snort training in an authorized laboratory;
- IDS versus IPS conceptual understanding;
- signature-, behaviour- and policy-based detection concepts;
- Snort configuration validation;
- sniffer-mode parameter practice;
- packet logging;
- binary and ASCII log handling;
- retained packet-log review;
- BPF-based packet filtering;
- IDS alert-mode practice;
- inline IPS concepts;
- PCAP investigation with Snort;
- single- and multi-PCAP processing;
- Snort rule-header understanding;
- rule-action understanding;
- address, port and direction filtering;
- payload and non-payload rule options;
- local rule creation and controlled testing;
- Snort configuration-variable familiarity;
- DAQ concept familiarity;
- Snort processing-pipeline understanding;
- guided rule-development practice.

The evidence does **not** support claims of:

- production IDS/IPS administration;
- independent enterprise Snort deployment;
- production inline traffic blocking;
- production custom-rule ownership;
- production network-monitoring responsibility;
- customer incident-response ownership;
- enterprise ruleset lifecycle management;
- production detection-engineering ownership;
- production packet-capture administration.

## Portfolio value

This room extends earlier packet-analysis and network-forensics training by
adding rule-driven network detection.

The progression can be represented as:

`Wireshark → detailed packet analysis`

`NetworkMiner → rapid host/artifact-oriented forensic triage`

`Snort → rule-driven detection, logging and alerting`

Together these exercises demonstrate a broader network-security-monitoring
workflow:

`network evidence → traffic analysis → automated detection → analyst validation`

The public evidence remains explicitly limited to guided laboratory practice.

## Next room recommended by the training

The room concludes by directing learners to continue with:

**Snort Challenge — The Basics**

That challenge is the next practical step for applying the Snort rule and
detection concepts introduced here.
