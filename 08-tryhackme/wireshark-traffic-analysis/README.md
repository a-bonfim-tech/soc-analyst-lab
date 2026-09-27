# TryHackMe — Wireshark: Traffic Analysis

## Training state

**COMPLETED — GUIDED HANDS-ON TRAINING**

- Platform: TryHackMe
- Learning path: SOC Level 1
- Module: Network Traffic Analysis
- Room: Wireshark: Traffic Analysis
- Completion: 100%
- Environment: authorized TryHackMe Wireshark laboratory
- Practical scope: network anomaly detection, packet correlation, protocol analysis, traffic tunnelling analysis, cleartext protocol investigation, TLS decryption and actionable network findings
- Portfolio relationship: packet-level investigation and network-traffic analysis for SOC workflows

This record documents guided hands-on network-traffic analysis performed inside
the room-provided Wireshark laboratory.

The exercise extended earlier packet-operation skills into investigation and
correlation. Instead of using Wireshark only to locate individual packets or
apply filters, the work focused on combining packet-level observations into
analyst findings about scanning, spoofing, tunnelling, authentication,
cleartext protocols, encrypted traffic and suspicious web activity.

It does **not** represent:

- professional SOC employment;
- production network monitoring;
- enterprise packet-forensics ownership;
- production NDR administration;
- packet capture from an employer or customer environment;
- independent acquisition of forensic network evidence;
- production IDS/IPS administration;
- live containment of an attacker;
- customer incident response;
- production firewall administration;
- investigation of a real employer, customer or third-party incident.

TryHackMe flags, challenge answers, credentials, answer-key values, screenshots
containing solutions, raw challenge packet captures and challenge-specific
endpoint identifiers are intentionally excluded.

## Practical investigation workflow

The room used multiple supplied packet captures to practise a broader
investigative workflow:

1. identify an investigation question;
2. establish relevant protocol behaviour;
3. scope the packet population;
4. inspect network conversations and packet fields;
5. identify anomalies;
6. correlate observations across related packets;
7. distinguish expected protocol behaviour from suspicious activity;
8. identify relevant hosts, users or services;
9. validate findings at packet level;
10. convert observations into analyst conclusions or defensive actions.

The reusable workflow is:

`PCAP → scope → correlate → identify anomaly → inspect evidence → validate → assess → act`

This is guided hands-on evidence from a controlled training environment, not
production incident-response experience.

## Nmap scan analysis

The exercise included recognition of common network-scanning patterns.

The analysis covered:

- TCP Connect scanning;
- TCP SYN scanning;
- UDP scanning;
- TCP flag interpretation;
- TCP handshake behaviour;
- open-versus-closed port response patterns;
- window-size context used by the exercise;
- ICMP responses associated with closed UDP ports.

The training reinforced that scan identification depends on understanding both
packet structure and expected protocol state transitions.

Relevant analytical concepts included:

`SYN → response pattern → handshake state → scan interpretation`

and:

`UDP probe → ICMP unreachable response → closed-port evidence`

The exercise also reinforced that analysts should not identify a scan solely
from one isolated packet when broader traffic context is available.

## ARP poisoning and MITM analysis

The room introduced packet-level investigation of ARP anomalies and
man-in-the-middle behaviour.

The analysis included:

- ARP requests;
- ARP replies;
- ARP opcode interpretation;
- duplicate IP-to-MAC claims;
- conflicting ARP information;
- possible ARP flooding;
- suspicious address ownership changes;
- correlation between ARP anomalies and later application traffic.

A key investigative principle was that a conflicting ARP observation is not
automatically sufficient to identify the malicious host.

The workflow required correlation:

`ARP conflict → address ownership review → suspicious MAC behaviour → related traffic → MITM hypothesis`

The exercise demonstrated why MAC-layer context can reveal anomalies that are
not obvious when examining only IP addresses.

## Host and user identification

The room used several protocols to identify hosts and users observed in network
traffic.

### DHCP

DHCP traffic was used to investigate:

- hostnames;
- requested IP addresses;
- lease information;
- client identifiers;
- request, acknowledgement and rejection behaviour.

The retained analytical concept is:

`DHCP event → hostname/client context → IP assignment context`

### NetBIOS

NetBIOS name-service traffic was used to extract host-identification context
from query and registration activity.

This demonstrated another source of endpoint identity information available in
packet captures.

### Kerberos

Kerberos traffic was used to identify user and host information in Windows
domain authentication traffic.

The exercise reinforced the distinction between:

- user account names;
- computer-account names;
- realm/domain information;
- service names;
- authentication-related network context.

The broader SOC lesson is that packet analysis can support attribution of
network activity to a host or account when the relevant protocol metadata is
available.

## DNS and ICMP tunnelling

The room introduced detection concepts for protocol tunnelling.

### ICMP tunnelling

The analysis focused on indicators such as:

- unusual ICMP volume;
- anomalous packet sizes;
- unexpected payload data;
- signs of another protocol encapsulated in ICMP traffic.

The retained investigative pattern is:

`trusted protocol → abnormal payload/volume → encapsulation evidence → tunnelling hypothesis`

The exercise reinforced that ICMP is legitimate network-control traffic and
therefore suspicious activity must be established through context rather than
protocol presence alone.

### DNS tunnelling

DNS analysis focused on indicators such as:

- unusually long query names;
- encoded-looking subdomains;
- abnormal request volume;
- repetitive queries toward a particular domain;
- patterns associated with DNS tunnelling tools.

The retained workflow is:

`DNS baseline → anomalous query structure → repeated target → encoded data hypothesis → packet validation`

This provided guided experience identifying how a normally trusted protocol can
be abused for command-and-control or data-exfiltration channels.

## FTP investigation

The FTP exercise demonstrated why cleartext protocols remain important in
network investigations.

The analysis included:

- FTP response-code interpretation;
- successful and failed authentication;
- username and password commands;
- repeated login failures;
- file access;
- file upload activity;
- directory and file operations;
- permission-related commands.

The exercise connected packet-level protocol analysis with several SOC-relevant
behaviours:

- brute-force indicators;
- credential exposure;
- unauthorized file transfer;
- possible malware staging;
- data-exfiltration context.

The retained workflow is:

`FTP session → authentication activity → file operation → suspicious command → analyst assessment`

## HTTP investigation

The HTTP exercise expanded packet analysis into web-traffic investigation.

The analysis included:

- request methods;
- response status codes;
- request URIs;
- host information;
- server metadata;
- user-agent values;
- web-form and cleartext content where available.

The room demonstrated several uses of HTTP traffic for threat investigation,
including:

- phishing-related traffic;
- web attacks;
- data exfiltration;
- command-and-control activity.

## User-Agent anomaly analysis

User-Agent fields were investigated as one source of anomaly evidence.

The exercise included identifying:

- unusual User-Agent strings;
- inconsistent User-Agent values from the same host;
- non-standard tool identifiers;
- subtle spelling differences;
- security-tool signatures;
- possible payload content embedded in User-Agent data.

The principal lesson is that User-Agent information is useful enrichment but
should not be treated as a standalone trust decision.

The retained principle is:

`User-Agent anomaly + surrounding traffic context → stronger investigative signal`

## Log4j-related traffic analysis

The HTTP investigation also included guided analysis of traffic patterns
associated with exploitation attempts involving Log4j.

The work focused on:

- locating suspicious HTTP requests;
- identifying known exploit-related string patterns;
- inspecting relevant packet fields;
- identifying encoded command material;
- decoding relevant content;
- identifying subsequent network communication associated with the activity.

The training value is the investigation sequence:

`web request → exploit indicator → encoded content → decode → network destination → correlated finding`

This was a guided training scenario and does not establish independent
vulnerability-research or production incident-response experience.

## HTTPS and TLS analysis

The room introduced investigation of encrypted HTTPS traffic.

Before decryption, the analysis included:

- TLS traffic identification;
- Client Hello messages;
- Server Hello messages;
- identification of communicating endpoints;
- TLS handshake context.

The room then used supplied TLS key-log material to make encrypted application
traffic available for analysis in Wireshark.

After decryption, the exercise included inspection of:

- HTTP/2 traffic;
- decompressed protocol metadata;
- decrypted application data;
- request authority information;
- reconstructed traffic context.

The retained workflow is:

`TLS session → handshake identification → key-log material → decryption → HTTP/2 inspection → application-layer evidence`

This demonstrates guided use of TLS session keys in a laboratory. It does not
represent compromise of encryption, unauthorized decryption or production TLS
inspection.

## Cleartext credential hunting

The exercise demonstrated Wireshark's ability to identify credentials exposed
through supported cleartext protocols.

The work included:

- reviewing automatically extracted credential information;
- locating the associated packet;
- correlating username and password events;
- identifying authentication attempts with missing or exposed password data;
- validating automated extraction against the packet evidence.

A key analytical principle was retained:

automated credential extraction is an investigative aid, not a substitute for
manual packet validation.

The workflow is:

`credential detection → packet reference → protocol validation → authentication context`

## Actionable results

The room concluded by connecting packet analysis with defensive action.

Wireshark's firewall-rule generation functionality was used to examine how
packet context can be converted into candidate access-control rules for several
firewall technologies.

The exercise demonstrated the transition from:

`observation → validated network indicator → candidate defensive rule`

This is useful as a SOC workflow concept, but the generated rules were part of a
training environment.

It does **not** demonstrate:

- production firewall change authority;
- production rule deployment;
- enterprise change-management approval;
- real-world containment execution.

## Analyst workflow retained from the room

The principal workflow learned from the room is:

`network telemetry → anomaly → packet correlation → protocol interpretation → attribution context → evidence validation → analyst finding → defensive recommendation`

The investigation reinforced several principles:

1. understand normal protocol behaviour before classifying an anomaly;
2. correlate multiple packets rather than relying on isolated indicators;
3. move between aggregate traffic patterns and packet-level evidence;
4. use multiple protocol layers when attribution requires additional context;
5. distinguish suspicious behaviour from proof of malicious activity;
6. validate tool-generated observations manually;
7. use cleartext protocol data carefully because it may contain sensitive information;
8. treat encrypted traffic metadata as useful even before decryption;
9. preserve the distinction between observed evidence and analytical inference;
10. convert validated findings into actionable analyst outputs where appropriate.

## Evidence boundary

The evidence supports:

- hands-on Wireshark traffic analysis in an authorized laboratory;
- packet-level network anomaly investigation;
- TCP Connect scan analysis;
- TCP SYN scan analysis;
- UDP scan analysis;
- TCP flag and handshake interpretation;
- ARP request and response analysis;
- ARP conflict investigation;
- guided ARP poisoning and MITM analysis;
- DHCP-based host identification;
- NetBIOS-based host identification;
- Kerberos-based host and user identification;
- ICMP tunnelling investigation;
- DNS tunnelling investigation;
- FTP authentication and file-operation analysis;
- HTTP request and response analysis;
- User-Agent anomaly investigation;
- guided Log4j-related HTTP traffic analysis;
- TLS handshake analysis;
- guided HTTPS decryption using supplied key-log material;
- HTTP/2 packet inspection after decryption;
- cleartext credential hunting;
- packet-to-firewall-rule workflow exposure;
- evidence correlation across multiple packets and protocols.

The evidence does **not** support claims of:

- production network monitoring;
- enterprise NDR ownership;
- live packet capture from a customer environment;
- independent forensic evidence acquisition;
- production IDS/IPS administration;
- production firewall administration;
- real-world ARP attack containment;
- production malware traffic analysis;
- independent Log4j incident response;
- unauthorized TLS decryption;
- customer credential investigation;
- production threat hunting;
- live network containment;
- professional SOC employment.

## Relationship to Wireshark: Packet Operations

`Wireshark: Packet Operations` established the operational foundation:

`PCAP → statistics → endpoint/conversation scoping → protocol filtering → packet inspection`

This room extended that foundation into investigation:

`packet evidence → anomaly → correlation → attribution context → threat hypothesis → actionable result`

The progression demonstrates a shift from operating Wireshark effectively to
using Wireshark as part of a structured SOC investigation workflow.

## Relationship to earlier SOC training

Earlier TryHackMe exercises established:

`alert → investigation → verdict → closure or escalation`

and:

`telemetry → query → relevant event subset → analyst interpretation`

The Wireshark sequence adds network-packet evidence:

`network traffic → packet capture → anomaly detection → protocol correlation → evidence assessment`

Together, these exercises broaden the portfolio across alert, log and
packet-level investigation while keeping the distinction between guided
training and production SOC experience explicit.

## Relationship to SOC-2026-006

This room is complementary to the already completed SOC-2026-006 investigation.

It reinforces skills relevant to that case in:

- network-telemetry interpretation;
- source/destination reasoning;
- host and user identification;
- protocol-level investigation;
- anomaly detection;
- evidence correlation;
- tunnelling indicators;
- authentication analysis;
- web-traffic investigation;
- packet-level timeline reconstruction;
- evidence-versus-assumption discipline;
- translating findings into defensive recommendations.

This TryHackMe room does **not** constitute or replace the Microsoft-platform
runtime evidence retained for SOC-2026-006.

SOC-2026-006 separately contains evidence of:

- Defender for Endpoint onboarding and telemetry;
- genuine Defender alert generation;
- Defender XDR incident handling;
- Microsoft Sentinel ingestion;
- Microsoft Sentinel KQL execution;
- retained Sentinel query evidence;
- analyst-authored laboratory ticketing;
- severity reassessment;
- incident disposition and closure.

The Wireshark training therefore provides complementary packet-analysis practice,
while SOC-2026-006 remains the separate completed Microsoft Defender/XDR/Sentinel
SOC investigation.

## Portfolio value

This exercise provides hands-on evidence that I can move beyond packet
filtering and use Wireshark to investigate suspicious network behaviour.

The demonstrated analytical chain is:

`capture → detect → correlate → investigate → validate → assess → recommend`

Its portfolio value is the combination of packet-level technical analysis with
SOC-oriented reasoning across scanning, spoofing, tunnelling, authentication,
web traffic, encrypted traffic and defensive follow-up.

The evidence boundary remains explicit: all work was completed in an authorized
TryHackMe laboratory using room-provided training captures and materials, not in
a production SOC or customer network.
