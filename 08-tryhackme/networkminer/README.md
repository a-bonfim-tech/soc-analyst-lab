# TryHackMe — NetworkMiner

## Training state

**COMPLETED — GUIDED HANDS-ON TRAINING**

- Platform: TryHackMe
- Learning path: SOC Level 1
- Module: Network Traffic Analysis
- Room: NetworkMiner
- Environment: authorized TryHackMe laboratory
- Primary tool: NetworkMiner
- Practical scope: PCAP triage, network-forensics overview, host and session analysis, artifact extraction, credential discovery, DNS inspection and anomaly review
- Portfolio relationship: guided network-forensics and PCAP-analysis practice for SOC workflows

This record documents guided hands-on work performed in the room-provided
laboratory.

The training focused on using NetworkMiner as a Network Forensic Analysis Tool
(NFAT) to obtain a rapid overview of captured network traffic and extract useful
investigative context before deeper packet-level analysis.

It does **not** represent:

- professional SOC employment;
- production network monitoring;
- production network-forensics ownership;
- independent acquisition of forensic evidence;
- live customer incident response;
- production credential harvesting;
- production IDS operation;
- production packet capture;
- investigation of an employer or customer network;
- independent malware analysis;
- production containment activity.

TryHackMe challenge answers, credentials, hashes, challenge-specific IP
addresses, personal names used by exercises, exact answer-key frame numbers,
screenshots containing solutions and raw challenge PCAPs are intentionally
excluded.

## What NetworkMiner is

The room presents NetworkMiner as an open-source Network Forensic Analysis Tool.

Its relevant capabilities include:

- parsing captured network traffic;
- identifying hosts;
- identifying sessions;
- identifying open ports;
- OS fingerprinting;
- extracting files;
- extracting images;
- extracting message content;
- extracting authentication material where exposed in captured traffic;
- extracting cleartext parameters and keywords;
- displaying DNS activity;
- surfacing selected anomalies.

NetworkMiner can also operate as a traffic sniffer, but the room explicitly
discourages treating it as a primary sniffer.

The recommended role is network-forensics triage and PCAP processing.

## Network-forensics purpose

The room frames the objective of network forensics as extracting sufficient
information from network traffic to investigate:

- malicious activity;
- security breaches;
- network anomalies;
- suspicious hosts;
- unusual sessions;
- potential attack indicators;
- tools associated with suspicious activity.

Three data categories are introduced for network forensics:

1. live traffic;
2. traffic captures;
3. log files.

The room concentrates on captured traffic and NetworkMiner's ability to process
PCAP data.

## Operating model

The training distinguishes two principal operating modes.

### Sniffer mode

NetworkMiner can collect traffic in supported environments.

However, the room warns that its sniffing functionality should not be treated as
a replacement for dedicated packet-capture tools.

The practical lesson retained is:

`capture tool → PCAP → NetworkMiner triage`

rather than:

`NetworkMiner → primary enterprise sniffer`

### Packet parsing and processing

This is the primary NetworkMiner workflow used in the room.

Captured traffic is loaded into NetworkMiner to identify useful investigative
information quickly.

The room characterises this as finding the investigative "low hanging fruit"
before moving to deeper analysis.

The retained workflow is:

`PCAP → rapid overview → identify artifacts/context → select leads → deeper analysis`

## Case management

The Case Panel provides visibility into loaded capture files.

The room demonstrated that an analyst can:

- load a PCAP;
- identify the active case file;
- refresh or reload the case;
- inspect case metadata;
- remove loaded case data.

This provides basic case-level context before examining individual artifacts.

## Host analysis

The Hosts view provides a consolidated view of systems identified in captured
traffic.

Relevant information includes:

- IP-address context;
- MAC-address context;
- operating-system information;
- open ports;
- sent packets;
- received packets;
- incoming sessions;
- outgoing sessions;
- host details.

The room also introduces OS fingerprinting through external fingerprinting data
used by NetworkMiner.

The retained workflow is:

`PCAP → host inventory → host attributes → communication context → investigative lead`

Host metadata should be treated as evidence requiring context rather than as an
automatic determination of maliciousness.

## Session analysis

The Sessions view provides communication-level context.

The room demonstrates inspection of information such as:

- client address;
- server address;
- source port;
- destination port;
- protocol;
- frame association;
- session start time.

NetworkMiner supports searches within this view and several search modes,
including exact phrases, all-word matching, any-word matching and regular
expressions.

The practical workflow is:

`host pair → session → ports → protocol context → traffic volume → analyst interpretation`

The exercises reinforced using session metadata to understand communication
between hosts without beginning with manual packet-by-packet inspection.

## DNS analysis

The DNS view exposes DNS-related activity observed in a capture.

Relevant fields include:

- client and server context;
- source and destination ports;
- timestamps;
- transaction information;
- query information;
- answer information;
- TTL-related context.

This supports workflows such as:

`host → DNS activity → queried resource → surrounding network context`

DNS information is investigative context and should be correlated with other
evidence before assigning meaning to an observed query.

## Credential discovery

NetworkMiner can extract authentication-related material present in captured
traffic.

The room discusses support for several protocols and authentication mechanisms,
including examples involving:

- Kerberos;
- NTLM;
- RDP-related data;
- HTTP;
- IMAP;
- FTP;
- SMTP;
- database traffic.

The analyst lesson is not simply to collect extracted values.

The relevant workflow is:

`captured authentication traffic → extracted artifact → protocol context → validation → investigative finding`

Authentication material can be highly sensitive. No credentials or
challenge-specific authentication material are retained in this repository.

## File extraction

The Files view exposes artifacts reconstructed from captured network traffic.

Available context can include:

- frame association;
- filename;
- extension;
- size;
- source host;
- destination host;
- source port;
- destination port;
- protocol;
- timestamp;
- reconstructed path;
- artifact details.

The room demonstrates that reconstructed files can provide investigative context
that is difficult to obtain from aggregate traffic statistics alone.

The retained workflow is:

`network communication → reconstructed file → metadata → content inspection → contextual finding`

## Image extraction

NetworkMiner can reconstruct images observed in network traffic.

The Images view can expose contextual information such as:

- source;
- destination;
- file path;
- associated network activity.

The training used image extraction as another way to connect application-layer
content with network communication.

The relevant principle is:

`artifact content + network origin + destination context → stronger evidence`

## Parameter extraction

The Parameters view exposes values reconstructed from supported traffic.

Relevant information can include:

- parameter name;
- parameter value;
- frame association;
- source host;
- destination host;
- source port;
- destination port;
- timestamp;
- additional details.

This supports rapid discovery of useful application-layer information without
requiring the analyst to inspect every packet manually.

Extracted parameters still require contextual validation.

## Keyword analysis

NetworkMiner can search processed capture data for analyst-defined keywords.

The room demonstrates that analysts can:

1. define keywords;
2. reload the relevant case data;
3. search processed content;
4. identify matching network context;
5. correlate a hit with hosts and communications.

The retained workflow is:

`investigative term → keyword search → context hit → host/session correlation → validation`

Keyword hits are leads, not proof by themselves.

## Messages

The Messages view can expose communication artifacts such as email, chat or
other message content reconstructed from captured traffic.

Relevant context can include:

- sender;
- receiver;
- protocol;
- timestamp;
- source host;
- destination host;
- size;
- attachments;
- message attributes.

The room demonstrates using this information to connect reconstructed message
content with network activity.

This is useful for network-forensics triage but does not replace broader
evidence handling or incident-response procedures.

## Anomalies

NetworkMiner contains limited anomaly-detection functionality.

The room explicitly notes that NetworkMiner is **not an IDS**.

Its anomaly view may nevertheless provide leads related to selected suspicious
conditions or attack patterns.

Therefore the correct analytical model is:

`tool-generated anomaly → investigative lead → packet/session validation → analyst assessment`

not:

`tool-generated anomaly → automatically confirmed incident`

## NetworkMiner version differences

The room uses two major versions to demonstrate meaningful feature differences.

### NetworkMiner 2.x / 2.7

The newer version provides capabilities including:

- MAC-address-oriented correlation;
- identification of possible duplicate MAC-address conditions;
- more extensive parameter processing.

These features can improve host correlation and rapid application-data
discovery.

### NetworkMiner 1.6

The older version retains functionality that is useful for some specific
investigations, including:

- frame-oriented inspection;
- additional packet-detail visibility;
- a dedicated cleartext-data view.

The room therefore demonstrates an important tooling lesson:

**newer does not always mean that every previous investigative view remains
available in the same form.**

Version selection can affect which evidence views are available.

## NetworkMiner and Wireshark

The room distinguishes the practical roles of NetworkMiner and Wireshark.

NetworkMiner is oriented toward:

- rapid traffic overview;
- host discovery;
- session mapping;
- OS fingerprinting;
- artifact reconstruction;
- parameter discovery;
- credential discovery;
- host categorisation;
- fast extraction of investigative leads.

Wireshark is oriented toward:

- detailed packet inspection;
- advanced filtering;
- protocol decoding;
- payload inspection;
- deeper protocol analysis;
- statistical investigation.

The recommended combined workflow is:

`PCAP → NetworkMiner overview → identify leads → Wireshark/tcpdump deeper analysis`

This is the principal tool-combination lesson retained from the room.

## Practical exercises

The room's exercises required applying NetworkMiner to supplied PCAP files.

Without retaining challenge answers, the practical work included:

- identifying operating-system context associated with a host;
- investigating communications between specific hosts;
- examining session directionality;
- comparing client and server traffic volumes;
- working with port-level communication context;
- inspecting frame-related information;
- identifying content-type information;
- extracting hardware or device-related context;
- identifying application/device information from captured traffic;
- tracing an extracted image to its network source;
- identifying authentication information exposed in traffic;
- locating DNS activity associated with captured communications.

These exercises required moving between NetworkMiner views rather than relying
on a single result page.

## Investigation workflow retained from the room

A reusable NetworkMiner workflow is:

`PCAP`
`→ case overview`
`→ hosts`
`→ sessions`
`→ DNS`
`→ artifacts`
`→ parameters/keywords/messages`
`→ credentials/anomalies where relevant`
`→ correlate findings`
`→ deeper packet analysis`

A more compact formulation is:

`PCAP → triage → extract → correlate → validate → escalate to deeper analysis`

## Analyst lessons

The room reinforces several operational principles:

1. use NetworkMiner primarily as a Network Forensic Analysis Tool;
2. do not rely on it as the primary network sniffer;
3. begin with rapid traffic mapping before detailed packet analysis;
4. use host and session views to establish communication context;
5. use artifact extraction to identify relevant content quickly;
6. correlate extracted information with its source and destination;
7. treat automatically extracted credentials and parameters as sensitive data;
8. treat anomaly detection as lead generation rather than incident confirmation;
9. understand tool-version differences before assuming a feature is unavailable;
10. move to Wireshark or tcpdump when deeper packet-level investigation is required.

## Evidence boundary

The evidence supports claims of:

- guided hands-on NetworkMiner use in an authorized laboratory;
- PCAP parsing and triage;
- network-forensics workflow practice;
- host identification and categorisation;
- session analysis;
- port and protocol-context review;
- operating-system fingerprinting;
- DNS inspection;
- reconstructed file analysis;
- reconstructed image analysis;
- parameter extraction;
- keyword-based investigation;
- message reconstruction;
- authentication-artifact discovery;
- anomaly-review workflow;
- comparison of NetworkMiner 1.6 and 2.7 capabilities;
- correlation of host, session and artifact evidence;
- transition from rapid PCAP triage to deeper Wireshark/tcpdump analysis.

The evidence does **not** support claims of:

- production SOC employment;
- enterprise network-forensics ownership;
- production packet-capture administration;
- independent forensic acquisition;
- production credential harvesting;
- production IDS administration;
- customer incident-response ownership;
- production threat hunting;
- independent malware analysis;
- production containment;
- enterprise firewall administration.

## Portfolio value

This training extends the packet-analysis work documented in earlier Wireshark
training by adding an artifact-centric and host-centric network-forensics
workflow.

The combined training model is:

`NetworkMiner → rapid triage and extraction`

followed by:

`Wireshark / tcpdump → deeper packet-level validation`

For a SOC portfolio, the value is therefore not merely familiarity with another
GUI tool. The evidence demonstrates a broader investigative process for moving
from captured network traffic to hosts, sessions, artifacts and validated leads
while preserving the distinction between guided laboratory practice and
production experience.
