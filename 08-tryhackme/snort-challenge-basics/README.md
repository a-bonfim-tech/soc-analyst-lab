# TryHackMe — Snort Challenge: The Basics

## Training state

**COMPLETED — GUIDED HANDS-ON TRAINING**

- Platform: TryHackMe
- Learning path: SOC Level 1
- Module: Network Security Monitoring
- Room: Snort Challenge — The Basics
- Environment: authorized TryHackMe laboratory
- Primary technology: Snort 2
- Practical scope: IDS rule creation, rule troubleshooting, packet-log investigation, payload inspection and external-rule analysis
- Portfolio relationship: guided rule-based network-detection practice for SOC and Blue Team workflows

This record documents guided hands-on work completed in the room-provided
laboratory.

The challenge builds on the preceding Snort fundamentals room by requiring the
learner to apply Snort rules to captured network traffic, investigate generated
logs and alerts, troubleshoot defective rules and work with supplied detection
content for known vulnerabilities.

No TryHackMe answer keys, exercise-specific packet counts, IP addresses,
hostnames, request paths, packet field values, challenge-specific rule IDs,
decoded attacker commands, PCAP filenames or raw challenge artifacts are
retained in this repository.

## Training objective

The practical objective was to move from understanding Snort syntax to applying
rule-based detection against realistic network evidence.

The room required work across several detection scenarios:

1. HTTP traffic;
2. FTP traffic;
3. file-signature identification;
4. torrent/metafile traffic;
5. rule syntax troubleshooting;
6. rule logic troubleshooting;
7. external rules associated with MS17-010;
8. external rules associated with Log4j.

The overall workflow can be represented as:

`network evidence`

`→ detection hypothesis`

`→ Snort rule`

`→ rule execution`

`→ alert/log generation`

`→ packet investigation`

`→ result validation`

`→ rule refinement`

## HTTP rule-writing practice

The HTTP exercise required creating a Snort IDS rule that identifies TCP traffic
associated with the standard HTTP service port.

The task then required analysing the resulting Snort logs and examining
packet-level metadata.

Investigation included fields such as:

- source and destination addressing;
- source and destination ports;
- TCP acknowledgement information;
- TCP sequence information;
- IP time-to-live information;
- packet position within the generated evidence.

The relevant SOC lesson is that a detection alert is normally only the beginning
of the investigation.

A useful workflow is:

`rule match`

`→ locate corresponding packet`

`→ inspect packet metadata`

`→ establish traffic direction`

`→ validate network context`

## FTP rule-writing practice

The FTP exercises required progressively refining Snort rules for TCP traffic
associated with FTP.

The work included detecting:

- general FTP control traffic;
- unsuccessful authentication activity;
- successful authentication activity;
- username submission events;
- authentication attempts involving a selected account.

The exercise demonstrates an important detection-engineering principle:

**broad network detection should be progressively refined into behaviour-specific
detection.**

A simplified progression is:

`service traffic`

`→ protocol behaviour`

`→ authentication behaviour`

`→ specific detection condition`

This is directly relevant to SOC alert triage because broad rules may produce
large volumes of events while behaviour-oriented rules provide stronger
investigative context.

## Authentication-focused detection

The FTP exercises also reinforced the difference between detecting network
activity and detecting meaningful security behaviour.

For example, traffic on a service port establishes that the protocol is being
used, while authentication-related content can indicate:

- login attempts;
- repeated authentication failures;
- successful authentication;
- username enumeration;
- account-specific activity.

This progression mirrors a common SOC workflow:

`network connection`

`→ application transaction`

`→ authentication event`

`→ potentially suspicious behaviour`

## File-signature detection

Another part of the challenge required identifying image files transferred
inside captured traffic.

The exercises involved creating rules that detect file-signature patterns rather
than relying only on ports.

This reinforces the distinction between:

`service-based detection`

and:

`content-based detection`

File-type detection can use characteristic byte sequences or other recognisable
payload structures.

The practical lesson is that traffic classification should not rely exclusively
on port numbers.

Applications can operate over unexpected ports, and different content types can
travel over the same protocol.

## Payload inspection

The file-detection tasks required inspecting packet payload data after a Snort
rule generated relevant evidence.

This reinforced the workflow:

`signature match`

`→ alert`

`→ packet payload review`

`→ contextual interpretation`

Payload inspection can help determine:

- transferred file type;
- application metadata;
- protocol content;
- suspicious strings;
- embedded identifiers;
- exploit-related patterns.

No challenge-specific payload values are retained here.

## Torrent metafile detection

The room also required writing a rule capable of identifying traffic associated
with torrent metafiles.

The investigation involved examining metadata contained in the matched traffic
and using the generated logs to determine application-level context.

The important detection lesson is that Snort can identify activity using
payload characteristics rather than relying solely on IP addresses or ports.

The conceptual workflow is:

`network packet`

`→ content match`

`→ metadata identification`

`→ application/protocol context`

This approach is relevant to network security monitoring where analysts must
identify software or content types from traffic characteristics.

## Rule syntax troubleshooting

A major section of the room focused on intentionally defective Snort rules.

The objective was to diagnose and repair syntax errors before using the rules
against captured traffic.

The exercises reinforced the need to understand the complete rule structure:

`action`

`protocol`

`source address`

`source port`

`direction`

`destination address`

`destination port`

`rule options`

Typical troubleshooting considerations include:

- missing separators;
- malformed rule headers;
- incorrect option formatting;
- invalid punctuation;
- incomplete rule options;
- malformed content expressions;
- incorrect parameter placement.

The core operational principle is:

**a detection rule must be syntactically valid before its detection logic can be
evaluated.**

## Rule logic troubleshooting

The room also distinguished syntax errors from logical errors.

A syntactically valid rule can still fail to generate useful alerts if its
conditions do not correctly represent the intended behaviour.

This creates two separate validation stages:

`syntax validation`

followed by:

`detection-logic validation`

The second stage requires asking questions such as:

- Does the rule inspect the correct protocol?
- Does it apply to the correct traffic direction?
- Are the addresses and ports scoped correctly?
- Is the payload condition appropriate?
- Are required rule options present?
- Is the condition too broad?
- Is the condition too restrictive?

This distinction is central to practical detection engineering.

## Iterative rule development

The challenge reinforces an iterative rule-development method:

`write`

`→ execute`

`→ observe`

`→ troubleshoot`

`→ refine`

`→ retest`

A rule should not be considered useful merely because Snort accepts its syntax.

The analyst must also confirm that it:

- matches the intended evidence;
- avoids irrelevant matches where possible;
- produces interpretable alerts;
- provides useful investigation context.

## Working with external rules

The room introduced the use of supplied rule content for investigation of known
vulnerabilities.

This demonstrates a realistic SOC scenario in which analysts often consume
rules produced by:

- security vendors;
- threat-intelligence providers;
- open-source communities;
- internal detection-engineering teams.

The analyst still needs to understand:

- what the rule is detecting;
- which traffic caused the match;
- what evidence supports the alert;
- whether the activity is relevant to the environment.

External rules therefore do not remove the need for analyst validation.

## MS17-010 detection exercise

One scenario used rules associated with exploitation activity related to
MS17-010.

The practical work involved:

- applying provided detection content to captured traffic;
- reviewing generated alerts;
- writing an additional payload-oriented rule;
- investigating the corresponding network evidence;
- relating the traffic to the known vulnerability context.

The exercise demonstrates how signature-based IDS detection can support
investigation of exploit-related network activity.

No challenge-specific packet totals, network addresses, request paths or answer
values are retained.

## Vulnerability-oriented network investigation

The MS17-010 scenario reinforces a broader SOC workflow:

`known vulnerability`

`→ detection signature`

`→ network match`

`→ packet evidence`

`→ exploit-context assessment`

A vulnerability identifier by itself does not establish that exploitation
succeeded.

The network evidence must still be investigated.

This distinction is important when interpreting IDS alerts because a signature
match can represent:

- scanning;
- exploit attempts;
- successful exploitation;
- benign traffic matching a pattern;
- laboratory-generated activity.

Context determines the final interpretation.

## Log4j detection exercise

The room also included investigation of network traffic associated with Log4j
exploitation patterns.

The exercise required applying provided rules, identifying triggered detection
content and then developing an additional rule based on packet-size conditions.

The investigation also required examining encoded payload material and
interpreting the underlying command structure.

The transferable skills include:

- external-rule execution;
- multiple-rule alert analysis;
- payload-size filtering;
- encoded-content recognition;
- payload decoding;
- command interpretation;
- correlation between an IDS alert and packet-level evidence.

Challenge-specific encoded material, attacker infrastructure and decoded command
content are intentionally excluded.

## Packet-size-based detection

One part of the Log4j exercise required narrowing traffic using packet payload
size.

This introduces another useful Snort detection dimension:

`payload size`

rather than only:

`port`

or:

`content string`

Size-based filtering can help isolate traffic exhibiting a known structural
pattern.

However, payload size alone is rarely sufficient to establish maliciousness.

A stronger investigation combines multiple indicators:

`size condition`

`+ protocol context`

`+ payload characteristics`

`+ destination/source context`

`+ analyst validation`

## Encoded payload investigation

The room required recognising that suspicious network content may be encoded.

The analytical process is:

`alert`

`→ inspect payload`

`→ identify encoded structure`

`→ decode safely`

`→ interpret resulting content`

`→ determine security relevance`

The important principle is that encoding is not equivalent to encryption.

Encoded data may still reveal:

- commands;
- URLs;
- script content;
- configuration data;
- attacker instructions.

In a production investigation, decoded content should be handled as potentially
hostile data.

## Alert-to-packet correlation

Across the room, the exercises repeatedly required moving from a Snort alert
back to the underlying packet evidence.

This creates the following investigation model:

`Snort rule`

`→ alert`

`→ corresponding packet`

`→ header analysis`

`→ payload analysis`

`→ context`

`→ finding`

This is directly transferable to SOC Tier 1 work.

An analyst should not treat the alert text as the complete evidence set.

## Rule precision

The room demonstrates that Snort rules can operate at several levels of
specificity.

Examples include:

- protocol-level matching;
- service-port matching;
- traffic-direction matching;
- payload-content matching;
- file-signature matching;
- authentication-pattern matching;
- payload-size matching;
- exploit-signature matching.

The more specific a rule becomes, the more important controlled testing becomes.

Poorly designed rules can generate:

- excessive false positives;
- missed detections;
- ambiguous alerts;
- unnecessary processing overhead.

## Detection engineering fundamentals reinforced

The challenge reinforces several detection-engineering principles.

### Start with a hypothesis

Define what behaviour the rule is intended to detect.

### Select the correct traffic scope

Identify the relevant:

- protocol;
- ports;
- network direction;
- payload characteristics.

### Build incrementally

Add rule conditions progressively instead of creating a complex rule all at
once.

### Validate syntax

Ensure Snort can parse the rule.

### Validate logic

Confirm that the rule matches the intended traffic.

### Investigate matches

Review the generated evidence rather than relying only on alert counts.

### Refine

Adjust the rule when it is too broad, too narrow or operationally unclear.

## SOC workflow retained from the challenge

A reusable workflow from the room is:

`define detection objective`

`→ write or select rule`

`→ validate rule syntax`

`→ run against controlled traffic`

`→ review alerts`

`→ inspect corresponding packets`

`→ validate payload/header context`

`→ refine rule`

`→ retest`

This workflow links detection engineering with investigation rather than treating
them as separate disciplines.

## Practical skills demonstrated

The guided exercises provide evidence of practice with:

- Snort IDS rule creation;
- TCP traffic detection;
- HTTP-oriented traffic analysis;
- FTP-oriented traffic analysis;
- authentication-pattern detection;
- payload-content matching;
- binary/file-signature matching;
- application metadata investigation;
- rule syntax troubleshooting;
- rule logic troubleshooting;
- supplied/external Snort rules;
- exploit-related traffic investigation;
- packet-size detection conditions;
- encoded payload investigation;
- packet header analysis;
- packet payload analysis;
- alert-to-packet correlation;
- iterative rule refinement.

## Relationship to previous training

The previous Snort room introduced:

- Snort architecture;
- operating modes;
- configuration;
- logging;
- alerting;
- PCAP processing;
- rule structure.

This challenge moves the progression from:

`understand Snort`

to:

`apply Snort`

The broader network-analysis progression represented in the portfolio is:

`Wireshark → detailed packet analysis`

`NetworkMiner → host/artifact-oriented network forensic triage`

`Snort → rule-driven detection fundamentals`

`Snort Challenge — The Basics → practical rule creation and troubleshooting`

## Blue Team relevance

The room is particularly relevant to:

- SOC alert triage;
- network security monitoring;
- IDS investigation;
- detection engineering fundamentals;
- packet analysis;
- exploit detection;
- rule troubleshooting.

For a Tier 1 analyst, the central skill is not merely writing rules.

It is understanding how to move from:

`alert`

to:

`evidence`

to:

`context`

to:

`decision`

## Evidence boundary

The evidence supports claims of:

- completed guided Snort challenge training;
- practical IDS rule-writing exercises;
- HTTP and FTP detection-rule practice;
- authentication-pattern detection practice;
- payload-content matching;
- file-signature detection;
- torrent/metafile traffic detection;
- Snort syntax troubleshooting;
- Snort logic troubleshooting;
- external-rule usage;
- guided MS17-010 traffic investigation;
- guided Log4j traffic investigation;
- payload-size filtering;
- encoded payload analysis;
- packet metadata investigation;
- alert-to-packet correlation;
- iterative rule testing and refinement.

The evidence does **not** support claims of:

- production IDS administration;
- production Snort deployment;
- enterprise detection-engineering ownership;
- independent vulnerability exploitation;
- production incident-response ownership;
- production network monitoring responsibility;
- production custom-rule lifecycle ownership;
- production inline traffic blocking;
- independent threat-research ownership.

## Sanitisation policy

This repository intentionally excludes:

- TryHackMe answers;
- challenge-specific packet counts;
- challenge-specific IP addresses;
- challenge-specific hostnames;
- challenge-specific request paths;
- challenge-specific packet field values;
- challenge-specific rule identifiers;
- challenge-specific decoded commands;
- challenge-specific vulnerability-score answers;
- exercise PCAP filenames;
- generated challenge logs;
- raw PCAP files;
- screenshots containing solutions;
- credentials;
- flags;
- answer-key artifacts.

The objective is to document transferable SOC capability without publishing
challenge solutions.

## Portfolio value

This room provides stronger evidence than a purely conceptual Snort exercise
because it required repeated rule creation, execution, investigation,
troubleshooting and refinement.

The portfolio claim remains precise:

**guided hands-on network detection and Snort rule-analysis practice in an
authorized training environment.**

## Next room

The room concludes by directing learners to:

**Snort Challenge — Live Attacks**

That room is the next progression from offline rule analysis toward responding
to simulated live malicious traffic.
