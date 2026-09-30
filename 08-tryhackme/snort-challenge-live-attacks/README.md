# TryHackMe — Snort Challenge: Live Attacks

## Training state

**COMPLETED — GUIDED HANDS-ON TRAINING**

- Platform: TryHackMe
- Learning path: SOC Level 1
- Module: Network Security Monitoring
- Room: Snort Challenge — Live Attacks
- Environment: authorized TryHackMe laboratory
- Primary technology: Snort
- Practical scope: live-traffic observation, anomaly identification, IDS-to-IPS workflow, rule testing, inline blocking and post-detection validation
- Portfolio relationship: guided network-detection and traffic-containment practice for SOC and Blue Team workflows

This record documents guided hands-on work completed in the room-provided
laboratory.

The challenge extends the preceding Snort exercises from offline rule analysis
toward active monitoring and containment of malicious network behaviour.

The central progression is:

`observe traffic`

`→ identify anomalous behaviour`

`→ determine traffic direction and service context`

`→ develop a detection rule`

`→ test the rule`

`→ run Snort in IPS mode`

`→ block the malicious traffic`

`→ validate that the unwanted activity has stopped`

No TryHackMe flags, exercise-specific network addresses, challenge-specific
service answers, challenge-specific ports, attacker identifiers, exact solution
rules or answer-key material are retained in this repository.

## Training objective

The objective of the room was to use Snort against active network traffic rather
than only previously captured evidence.

The exercises required the learner to:

- observe live traffic;
- recognise suspicious patterns;
- distinguish inbound from outbound activity;
- determine which traffic required defensive action;
- create Snort rules;
- test rule behaviour;
- move from IDS-style observation to IPS-style blocking;
- validate whether the malicious traffic was actually stopped.

This represents a practical progression from:

`detect`

to:

`detect + contain`

## Scenario structure

The room contained two defensive scenarios:

1. a credential brute-force scenario;
2. a reverse-shell scenario.

The first scenario focused on malicious inbound access attempts.

The second scenario shifted the analyst's attention toward persistent outbound
traffic and the possibility that a host was already compromised.

Together, the two scenarios reinforce the need to monitor traffic in both
directions.

## Live traffic observation

The challenge began with live traffic inspection.

The analyst had to observe network behaviour before attempting to block it.

The relevant workflow is:

`live packets`

`→ traffic pattern`

`→ anomaly hypothesis`

`→ protocol/service context`

`→ detection decision`

This is important because blocking should follow evidence rather than assumption.

A defensive rule created before understanding the observed behaviour can be:

- too broad;
- too narrow;
- ineffective;
- operationally disruptive;
- difficult to validate.

## Sniffer-mode investigation

Snort was first used in a passive observation role.

The goal was to inspect active traffic and determine what behaviour appeared
abnormal.

This reinforces the separation between:

`observation`

and:

`intervention`

During the observation phase, useful analyst questions include:

- Which direction is the traffic moving?
- Is one host repeatedly contacting another?
- Is the activity persistent or burst-based?
- Is the pattern consistent with normal application behaviour?
- Is the same destination or service repeatedly involved?
- Does the traffic suggest authentication abuse?
- Does the traffic suggest a persistent remote-control channel?

The challenge required answering such questions before moving into blocking.

## Inbound brute-force scenario

The first defensive scenario involved repeated access attempts against a
network-exposed service.

The important lesson is not the challenge-specific service value.

The transferable behaviour is:

`repeated inbound connection or authentication activity`

`→ potential credential attack`

`→ detection rule`

`→ IPS enforcement`

A brute-force pattern may be characterised by:

- repeated connection attempts;
- repeated authentication-related exchanges;
- high-frequency activity from a source;
- repeated targeting of the same service;
- sustained activity inconsistent with normal user behaviour.

The analyst must first identify the pattern and then decide how narrowly the
rule should be scoped.

## Brute-force detection logic

A useful conceptual detection model is:

`source`

`+ destination`

`+ protocol`

`+ service context`

`+ repeated behaviour`

`→ suspicious access activity`

In a production environment, additional context could include:

- authentication logs;
- account lockout events;
- source reputation;
- geolocation context;
- historical login behaviour;
- endpoint telemetry;
- identity-provider events.

The TryHackMe exercise focused specifically on the network-detection component.

## Moving from IDS to IPS

The room required progressing from passive detection toward active blocking.

Conceptually:

`IDS`

means:

`observe → detect → alert`

while:

`IPS`

adds:

`observe → detect → enforce`

The distinction matters because detection and prevention have different
operational consequences.

A poorly scoped IDS rule may create noisy alerts.

A poorly scoped IPS rule may interrupt legitimate traffic.

Therefore, the challenge reinforced the sequence:

`inspect`

`→ understand`

`→ write`

`→ test`

`→ enforce`

rather than immediately blocking traffic.

## Rule testing before enforcement

The exercises required testing the rule before relying on it for blocking.

The practical lesson is:

**a rule that parses successfully is not automatically a useful defensive rule.**

The analyst must confirm that the rule:

- matches the intended traffic;
- generates the expected alert;
- targets the intended direction;
- does not rely on an incorrect assumption;
- can be applied without unnecessarily affecting unrelated traffic.

Testing provides evidence that the rule's detection logic corresponds to the
observed behaviour.

## Console-oriented validation

The room used console-visible alerting during rule validation.

This supports a useful development cycle:

`write rule`

`→ execute`

`→ observe alert`

`→ compare with live traffic`

`→ refine`

`→ retest`

Console-visible alerts make it easier to confirm that the rule is firing on the
intended traffic before moving to an enforcement configuration.

## Full alerting and IPS operation

After validating the rule, the exercise required running Snort in an IPS-oriented
mode while retaining alert/log evidence.

This combines two needs:

- stop malicious activity;
- preserve enough evidence to confirm why the block occurred.

A mature defensive workflow should avoid treating containment as the end of the
investigation.

Blocking is followed by validation.

## Containment validation

An important part of the challenge was maintaining the block long enough to
demonstrate that the malicious activity had actually been interrupted.

This reinforces the difference between:

`rule loaded successfully`

and:

`attack stopped successfully`

The second statement requires evidence.

A containment-validation workflow can be represented as:

`rule enabled`

`→ malicious traffic observed`

`→ rule matches`

`→ traffic blocked`

`→ malicious pattern ceases`

`→ defensive action validated`

## Reverse-shell scenario

The second scenario focused on persistent outbound traffic consistent with a
reverse-shell pattern.

This changes the analyst's perspective.

The first scenario asks:

`Who is trying to get in?`

The second asks:

`What if somebody is already inside?`

That distinction is highly relevant to SOC monitoring.

Preventing inbound access attempts does not prove that all hosts in the
environment are uncompromised.

## Outbound traffic analysis

The reverse-shell scenario reinforced the value of monitoring egress traffic.

Useful outbound indicators can include:

- persistent connections;
- unusual remote destinations;
- uncommon service relationships;
- long-lived sessions;
- repeated reconnection behaviour;
- interactive-looking traffic patterns;
- unexpected communication from an internal system.

The key lesson is:

**inbound blocking alone is not sufficient network defence.**

Internal hosts may already be compromised through:

- earlier exploitation;
- malicious software;
- stolen credentials;
- insider activity;
- another attack path.

Outbound visibility can expose behaviour that inbound-only monitoring misses.

## Reverse-shell behaviour

A reverse shell generally reverses the normal connection model.

Instead of an external operator directly initiating an interactive management
session into a target, the compromised host initiates or maintains an outbound
connection that provides remote command capability.

Conceptually:

`compromised host`

`→ outbound connection`

`→ remote operator infrastructure`

`→ interactive command channel`

This can be useful to an attacker because outbound traffic may encounter fewer
network restrictions than unsolicited inbound access.

## Detection perspective for reverse shells

The challenge required recognising the suspicious outbound behaviour before
creating the defensive rule.

The important transferable indicators include:

- persistent outbound connections;
- unexpected destination relationships;
- unusual protocol or service use;
- recurring connections from the same internal host;
- traffic inconsistent with the system's expected role.

No single indicator alone proves a reverse shell.

Context is required.

## Directionality as evidence

The room strongly reinforces the importance of traffic direction.

The analyst must distinguish:

`external → internal`

from:

`internal → external`

because the security interpretation can differ substantially.

Examples:

`external → internal repeated access attempts`

may suggest attempted intrusion.

`internal → external persistent interactive traffic`

may suggest post-compromise communication.

Direction therefore forms part of the detection hypothesis.

## Persistent traffic

Persistence was an important characteristic of the outbound scenario.

Persistent or recurring communication can be significant because many malicious
control channels are designed to:

- remain available;
- reconnect automatically;
- maintain remote access;
- survive temporary interruptions.

However, persistence itself is not malicious.

Legitimate applications also maintain long-lived connections.

The analyst must therefore correlate persistence with:

- host role;
- destination context;
- service context;
- traffic pattern;
- organisational expectations.

## IPS rule development

Both scenarios followed the same broad defensive engineering method:

`identify malicious pattern`

`→ define traffic scope`

`→ create rule`

`→ validate rule`

`→ enforce rule`

`→ observe result`

This is stronger than simply copying a rule because the learner must understand
what condition the rule is intended to control.

## Rule scope

An IPS rule should be scoped carefully.

Possible dimensions include:

- protocol;
- source network;
- destination network;
- traffic direction;
- source service context;
- destination service context;
- connection state;
- content characteristics;
- behavioural indicators.

The challenge demonstrates why precision matters.

A broad block may interrupt unrelated traffic.

A narrow block may fail to stop the malicious behaviour.

## Alert-to-action workflow

The room links detection directly to defensive action.

A reusable SOC workflow is:

`network anomaly`

`→ investigate`

`→ validate suspicious behaviour`

`→ create/select detection logic`

`→ test`

`→ contain`

`→ verify containment`

This connects monitoring, detection engineering and incident response.

## Detection versus containment

Detection answers:

`What suspicious activity is occurring?`

Containment answers:

`What action reduces or stops the immediate threat?`

The room requires both.

This is relevant to security operations because identifying malicious traffic
without acting on it may leave the system exposed.

At the same time, containment without understanding the evidence can create
unnecessary disruption.

## Evidence before blocking

A useful operational principle reinforced by the room is:

**observe before enforcing.**

The defensive process should establish enough context to justify the rule.

The challenge's structure intentionally requires the analyst to inspect the
traffic first and only then implement blocking.

This is consistent with controlled defensive practice.

## Continuous verification

Defensive action should be validated continuously.

Questions after enabling an IPS rule include:

- Is the malicious traffic still visible?
- Is the rule firing?
- Is the rule blocking the intended flow?
- Has the suspicious connection stopped?
- Is unrelated traffic still functioning?
- Does the event require escalation or further investigation?

The room focuses primarily on the first four questions.

## SOC Tier 1 relevance

The training is relevant to SOC Tier 1 work because it reinforces:

- network alert observation;
- anomaly recognition;
- traffic direction analysis;
- service/protocol contextualisation;
- defensive rule validation;
- alert-to-packet reasoning;
- escalation from detection to containment;
- post-action verification.

A Tier 1 analyst may not own production IPS rule deployment in every
organisation, but understanding how network enforcement works improves triage
quality.

## Network Security Monitoring relevance

The room connects several Network Security Monitoring concepts:

- live packet observation;
- directional analysis;
- behavioural interpretation;
- signature-based detection;
- rule validation;
- blocking;
- evidence preservation;
- containment verification.

This makes the exercise broader than simple Snort syntax practice.

## Relationship to previous Snort training

The progression represented by the Snort rooms is:

`Snort fundamentals`

`→ understand operating modes and rule structure`

then:

`Snort Challenge — The Basics`

`→ create and troubleshoot detection rules against controlled evidence`

then:

`Snort Challenge — Live Attacks`

`→ observe active malicious behaviour and use IPS enforcement to stop it`

This progression moves from:

`understand`

to:

`detect`

to:

`detect + contain`

## Relationship to previous network-analysis training

The broader portfolio progression is:

`Wireshark`

`→ detailed packet inspection`

`NetworkMiner`

`→ host/session/artifact-oriented network-forensic triage`

`Snort`

`→ rule-driven detection fundamentals`

`Snort Challenge — The Basics`

`→ rule creation, troubleshooting and alert-to-packet correlation`

`Snort Challenge — Live Attacks`

`→ live monitoring, detection and controlled IPS containment`

Together these exercises build a layered view of network security monitoring.

## Practical skills demonstrated

The guided exercises provide evidence of practice with:

- live network traffic observation;
- Snort sniffer-mode use;
- anomaly identification;
- inbound traffic investigation;
- outbound traffic investigation;
- brute-force-pattern recognition;
- reverse-shell-pattern recognition;
- traffic-direction analysis;
- protocol/service contextualisation;
- Snort rule creation;
- rule testing;
- console alert validation;
- IDS-to-IPS workflow;
- inline traffic blocking;
- defensive-rule verification;
- containment validation;
- alert-to-action reasoning.

## Evidence boundary

The evidence supports claims of:

- completed guided Snort live-attack training;
- live network-traffic observation practice;
- guided brute-force investigation;
- guided reverse-shell investigation;
- inbound/outbound traffic analysis;
- Snort rule-writing practice;
- Snort rule-testing practice;
- IPS-mode practice;
- controlled malicious-traffic blocking;
- post-block validation;
- guided SOC/Blue Team containment workflow practice.

The evidence does **not** support claims of:

- production IDS/IPS administration;
- production Snort deployment;
- enterprise firewall ownership;
- enterprise network-segmentation ownership;
- production detection-engineering ownership;
- production incident-response command authority;
- autonomous containment authority;
- production reverse-shell eradication;
- production credential-attack response ownership;
- independent malware analysis;
- independent threat-research ownership.

## Sanitisation policy

This repository intentionally excludes:

- TryHackMe flags;
- challenge-specific IP addresses;
- challenge-specific service answers;
- challenge-specific port answers;
- challenge-specific tool answers;
- exact challenge solution rules;
- exercise-specific attacker infrastructure;
- screenshots containing solutions;
- credentials;
- answer-key artifacts;
- copied room solution content.

The purpose is to document transferable defensive capability without publishing
challenge answers.

## Portfolio value

This challenge provides stronger operational evidence than a purely passive
packet-analysis exercise because it required progressing from observation to
active containment.

The portfolio claim remains precise:

**guided hands-on Snort live-traffic detection and IPS containment practice in an
authorized training environment.**
