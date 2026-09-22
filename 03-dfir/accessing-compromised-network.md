# Accessing a Compromised Network — DFIR Access Methodology

## Purpose

Document a defensible methodology for establishing access to a compromised
enterprise environment during a Digital Forensics and Incident Response (DFIR)
investigation.

The emphasis is not simply connectivity. Access decisions must consider:

- evidence integrity;
- forensic soundness;
- investigator operational security;
- contamination risk;
- scalability;
- separation of investigator and adversary activity;
- documentation and accountability.

## Scope

This case study was reconstructed from authorized hands-on training in an
isolated TryHackMe DFIR laboratory.

The public documentation intentionally excludes:

- room questions and answers;
- flags;
- passwords;
- authentication secrets;
- VPN portal information;
- target IP addresses;
- remote-access identifiers;
- cryptographic keys;
- challenge-specific filenames that constitute answers.

The objective is to document transferable DFIR methodology rather than reproduce
the laboratory solution.

## Scenario

An external DFIR investigator is brought into an enterprise environment after a
significant Active Directory compromise and confirmed data exfiltration.

The internal IT team detected the intrusion and isolated the environment before
the adversary could complete the anticipated ransomware-encryption phase.

The investigator must establish controlled access to affected infrastructure
while assuming that existing administrative endpoints, accounts, and workflows
may themselves be compromised.

## Investigation Objectives

The initial objectives were to:

1. determine an appropriate method for reaching the compromised environment;
2. preserve forensic integrity while establishing access;
3. avoid unnecessarily exposing investigative activity to a potentially active
   adversary;
4. obtain sufficient access to pivot between systems as new evidence emerged;
5. document investigator actions separately from ordinary administrative and
   attacker activity.

## Access Decision Framework

Three access strategies were considered.

| Method | Strength | Limitation | Appropriate use |
|---|---|---|---|
| VPN | Broad access to internal infrastructure through one controlled connection | May not reach isolated or remote endpoints | Enterprise servers and network-connected infrastructure |
| Remote desktop | Fast access to a specific endpoint, including systems outside normal VPN reach | Usually configured per host and can introduce new forensic artifacts | Remote or isolated endpoints requiring direct examination |
| On-site access | Does not depend on working remote infrastructure | Slow, expensive, and operationally heavier | Large incidents or environments where remote access is unavailable or unsafe |

The access method should therefore be selected according to investigative scope,
network availability, forensic risk, and the location of affected assets.

## Evidence-Integrity Considerations

During an active investigation, having ordinary IT personnel collect artifacts
on behalf of the DFIR investigator may introduce several problems.

### Collection consistency

Personnel who are not following the investigation's forensic acquisition
procedure may unintentionally alter, omit, or inconsistently collect evidence.

### Investigation latency

A repeated cycle of:

request → collection → transfer → analysis → new request

creates delays when an investigation requires rapid pivoting.

### Exploratory investigation

The complete artifact list cannot normally be known before analysis begins.

One artifact may expose another relevant:

- host;
- account;
- timestamp;
- process;
- log source;
- persistence mechanism;
- network path.

Direct investigator access therefore improves the ability to follow evidence as
the investigation develops.

## OPSEC Considerations

Existing administrative infrastructure cannot automatically be considered
trusted after compromise.

Potential risks include:

- a privileged administrative account being compromised;
- an administrator endpoint being monitored by the adversary;
- normal administrative workflows being visible to the attacker;
- investigative activity revealing which systems or evidence sources are under
  examination.

Screen sharing does not eliminate these risks if evidence acquisition still
occurs through the same administrator endpoint, account, and privileges.

## Dedicated Investigation Access

A better approach is a temporary access mechanism dedicated specifically to the
incident investigation.

Desired properties include:

- separate identity from ordinary administrator accounts;
- restricted use for the DFIR engagement;
- sufficient access for authorized forensic work;
- logging and monitoring;
- clear ownership;
- removal or disablement after the engagement.

This also makes investigator activity easier to distinguish from both normal
administrative activity and potential attacker activity.

## Remote Access to an Isolated Endpoint

Broad VPN access may still leave systems outside the reachable infrastructure.

In the training scenario, an isolated Windows web server required a separate
remote-access mechanism.

This introduced another forensic consideration: remote-management software is
frequently abused by attackers.

Examples of this technology category include legitimate remote administration
and support tools.

Before introducing such software into a compromised environment, the
investigator should determine whether the same mechanism was already used during
the intrusion.

If the attacker and investigator use the same remote-access technology, the
resulting artifacts may become difficult to attribute correctly.

Whenever practical, investigators should therefore prefer an access mechanism
that was not already associated with the incident.

## Authentication Layers

Remote-access authentication and operating-system authentication are separate
security boundaries.

Conceptually:

```text
Investigator
    |
    | Remote-access authentication
    v
Remote-access service
    |
    | Host connectivity
    v
Windows endpoint
    |
    | Operating-system authentication
    v
Authorized investigation session
```

These credentials and trust boundaries should not be confused during an
investigation.

## Investigator Activity

The remote session was used to access the isolated Windows web server.

The investigation proceeded through controlled inspection of the IIS web
content.

The relevant web directory was examined without intentionally modifying the
files under investigation.

File names, timestamps, and locations were treated as leads rather than proof
of malicious activity.

The determination was based on direct examination of file content.

## Web-Shell Finding

### Finding ID

THM-ACN-T3-001

### Asset

Isolated Windows/IIS laboratory web server.

### Artifact

PHP application file located within the IIS web root.

### Evidence

Direct inspection identified application code that accepted HTTP-controlled
input and passed that value to an operating-system command-execution primitive.

The construct also made command output available through the web application.

### Interpretation

The observed behavior provides remote operating-system command execution through
an HTTP request.

### Conclusion

The PHP application file contained functionality consistent with a web shell.

### Confidence

High.

### Basis

The assessment is based on directly observed command-execution functionality in
the application code rather than on filename, timestamp, size, or location
alone.

### Preservation

The file was examined but was not intentionally edited, renamed, moved, deleted,
or saved during inspection.

## Evidence vs. Interpretation

A core principle applied during the investigation was maintaining separation
between evidence and analytical conclusions.

Example:

**Evidence**

Application code accepts externally controlled HTTP input and passes it to an
operating-system command-execution function.

**Interpretation**

The functionality permits remote commands to be supplied through the web
application.

**Conclusion**

The examined application contains web-shell functionality.

This distinction reduces the risk of turning an observation into an unsupported
conclusion.

## Investigation Timeline

The investigative sequence was:

1. External DFIR access requirements were established.
2. Client-side collection through an ordinary administrator workflow was
   considered.
3. Direct investigator access was preferred based on evidence integrity,
   investigation speed, exploratory requirements, and OPSEC.
4. A dedicated investigation access mechanism was established.
5. Broad network access was found insufficient for an isolated endpoint.
6. A separate remote-access mechanism was used for the isolated system.
7. The investigator authenticated to the Windows laboratory host.
8. IIS web content was examined.
9. A suspicious PHP application artifact was inspected.
10. Direct command-execution functionality was identified.
11. The artifact was assessed as containing web-shell functionality.

## Lessons Learned

### Access is part of forensic methodology

Connecting to a compromised environment is not merely an IT administration
problem. The access method affects evidence integrity, attribution, OPSEC, and
investigation quality.

### Existing administrator infrastructure may be untrusted

Administrative endpoints and accounts cannot automatically be assumed clean
during an active compromise.

### Dedicated investigation identities improve separation

Temporary incident-specific access makes investigator activity easier to audit
and distinguish from routine administration.

### VPN and remote access solve different problems

VPN access is efficient for broad internal coverage but may not reach isolated
or remote endpoints.

### Remote-management tools create forensic artifacts

Introducing an access technology already used by an attacker may complicate
attribution.

### Investigator activity must remain identifiable

Actions performed during forensic examination should be documented and kept
distinguishable from adversary activity.

### Authentication layers must remain conceptually separate

Remote-access authentication and host operating-system authentication represent
different controls.

### Metadata alone is insufficient

Filename, timestamp, size, and location may support an investigation, but none
individually proves malicious behavior.

### Direct evidence is stronger

Inspection of the application logic provided stronger evidence than inference
from metadata.

### Minimize changes to evidence

Files under examination should not be unnecessarily saved, modified, renamed,
moved, or deleted.

## Portfolio Relevance

This exercise demonstrates practical understanding of:

- DFIR access planning;
- evidence integrity;
- incident-response OPSEC;
- remote-access risk;
- investigator activity separation;
- Windows server investigation;
- IIS artifact examination;
- evidence-based analysis;
- forensic documentation;
- distinction between evidence, interpretation, and conclusion.


## EDR and RMM Considerations

Endpoint-management platforms can provide an alternative to direct interactive
access during an incident.

Endpoint Detection and Response platforms may support:

- endpoint telemetry;
- forensic artifact collection;
- live-response actions;
- threat detection;
- containment;
- remote investigation.

Agent-based DFIR platforms can similarly support remote collection, host-state
analysis, threat hunting, and response operations.

These capabilities are most effective when the organization has deployed and
tested them before the incident.

Introducing unfamiliar remote-management tooling during an active compromise
creates additional risk.

Potential problems include:

- command timeouts;
- incomplete or truncated results;
- insufficient privileges;
- limited forensic capabilities;
- attacker visibility into management infrastructure;
- compromise of the management platform itself.

The investigation therefore favored known and controlled access mechanisms over
improvised use of unfamiliar management tooling.

## Network Access vs. Authentication

Network connectivity and authentication are separate controls.

A VPN may make an endpoint reachable without automatically granting access to
Windows, Active Directory, or application resources.

Conceptually:

```text
Network reachability
        |
        v
Authentication
        |
        v
Authorization
        |
        v
Forensic action
```

Each layer must be evaluated independently.

## Active Directory Access Planning

The investigation required considering whether a dedicated domain identity was
necessary.

Potential DFIR requirements included:

- collecting evidence across multiple systems;
- querying Active Directory;
- examining authentication activity;
- investigating domain controllers;
- resolving identities;
- accessing affected servers;
- pivoting between systems as evidence developed.

Read-only directory access may be sufficient for some investigative questions,
but it does not necessarily provide the endpoint-level permissions required for
forensic acquisition.

## Least Privilege

High privilege should not be used merely because it is available.

The preferred principle is:

> Use the minimum privilege capable of completing the authorized forensic task.

Some incident-response operations may require elevated privileges, but privilege
should remain scoped, justified, auditable, and temporary.

## Security Policy Exceptions

Incident urgency does not eliminate governance.

The training scenario included a conflict between an existing privileged-access
policy and the operational requirements of a remote incident investigation.

The appropriate response was escalation rather than bypass.

A defensible exception process should include:

- documented operational justification;
- management authorization;
- dedicated incident-specific identity;
- logging and accountability;
- defined lifetime;
- post-incident revocation.

This separates legitimate emergency access from uncontrolled policy violation.

## Initial Evidence Prioritization

High-value systems for early collection may include:

### Domain controllers

Useful for investigating:

- authentication activity;
- account use;
- privilege changes;
- directory modifications.

### Internet-facing systems

Potential entry points include:

- web servers;
- remote-access infrastructure;
- messaging services;
- virtual desktop infrastructure.

### Customer-identified suspicious hosts

Systems already associated with suspicious behavior should be evaluated early.

### Administrator workstations

Privileged workstations may expose:

- administrator credentials;
- attacker monitoring of remediation activity;
- access to high-value infrastructure;
- incident-response communications.

## RDP Forensic Considerations

Remote Desktop Protocol provides a complete interactive Windows session, but it
also increases the investigator footprint.

An interactive login may:

- create Windows events;
- modify user-state artifacts;
- alter timestamps;
- create session artifacts;
- expose credentials in memory;
- complicate separation between investigator and attacker activity.

RDP therefore remains useful, but should not automatically be selected when a
less intrusive access method can accomplish the forensic objective.

## WinRM for Remote DFIR

Windows Remote Management provides remote command-line access and underpins
PowerShell Remoting.

For incident response it offers several useful properties:

- remote PowerShell execution;
- automation;
- repeatability;
- operations across multiple endpoints;
- reduced dependence on graphical desktop sessions.

The laboratory demonstrated that successful WinRM use depends on several
prerequisites:

- appropriate local privilege;
- working WinRM service configuration;
- authentication configuration;
- valid credential objects;
- correct trust configuration where required.

## Troubleshooting Lessons

Several operational errors demonstrated useful troubleshooting principles.

### Privilege matters

Changes to local WinRM client configuration may require an elevated PowerShell
session.

### Commands should be isolated during troubleshooting

Combining several configuration commands into one malformed input makes it
difficult to identify the root cause.

Running commands independently improves fault isolation.

### Credential objects must exist before use

Remote-session commands that reference an uninitialized credential object will
fail before authentication even begins.

### Trust configuration affects remote authentication

Remote Windows management may require explicit trust configuration depending on
the authentication method and environment.

### Shell context matters

PowerShell cmdlets must be executed within PowerShell rather than assumed to be
native commands available in every Windows command interpreter.

## WinRM Session Behavior

The laboratory demonstrated an important distinction between interactive desktop
sessions and PowerShell Remoting.

A remote PowerShell session does not behave like a normal graphical RDP session
and therefore should not be expected to appear identically in interactive user
session enumeration.

This distinction matters when interpreting host telemetry during an
investigation.

## WMI for Remote Investigation

Windows Management Instrumentation provides another mechanism for remote system
discovery and administration.

Useful DFIR applications include:

- process discovery;
- system inventory;
- startup-entry enumeration;
- configuration inspection;
- remote querying;
- investigation at scale.

WMI does not provide the same interactive shell experience as PowerShell
Remoting, but it can expose valuable evidence even when interactive access is
not desirable or available.

## Persistence Investigation

Remote WMI enumeration of Windows startup commands identified an anomalous
startup entry.

The relevant evidence consisted of:

- a startup item with an unusual name;
- an executable launched from a user-writable public directory;
- persistence configured through a machine-level Windows Run key.

### Evidence

A startup command referenced an executable located under a public user-accessible
directory rather than a conventional application or operating-system location.

### Interpretation

An executable launched automatically from a user-writable directory is
suspicious because such locations are commonly more accessible to non-system
processes and users.

### Corroborating context

The command was registered through a Windows startup persistence mechanism.

### Assessment

The combination of:

```text
unusual executable
        +
user-writable path
        +
automatic startup
        +
machine-level Run key
```

was assessed as suspicious persistence requiring further investigation.

### Confidence

High for the presence of the persistence mechanism.

Additional evidence would still be required to independently attribute the
executable to a particular threat actor or intrusion stage.

## RDP, WinRM and WMI Comparison

| Method | Primary purpose | DFIR advantage | Primary concern |
|---|---|---|---|
| RDP | Interactive desktop | Full GUI access | Large forensic footprint |
| WinRM | Remote PowerShell | Automation and scalable command execution | Requires configuration and authentication |
| WMI | Remote querying | Broad discovery and inventory capabilities | Less interactive than a remote shell |

These technologies are complementary rather than interchangeable.

## Completed Investigation Workflow

The completed exercise can be represented as:

```text
Incident declared
        |
        v
Determine access requirements
        |
        v
Evaluate trust in existing customer infrastructure
        |
        v
Establish dedicated investigation connectivity
        |
        v
Determine authentication and privilege requirements
        |
        v
Select appropriate remote access method
        |
        +-------------------------------+
        |               |               |
        v               v               v
       RDP            WinRM            WMI
        |               |               |
 Interactive       Remote shell    Remote discovery
        |               |               |
        +---------------+---------------+
                        |
                        v
               Inspect forensic evidence
                        |
                        v
                 Correlate findings
                        |
                        v
               Document conclusions
```

## Additional Lessons Learned

### Connectivity is not authorization

Being able to reach a system does not mean the investigator is authenticated or
authorized to perform forensic actions.

### Investigator tooling leaves evidence

Remote-access mechanisms, interactive sessions, PowerShell Remoting, and WMI
queries all create observable activity.

Investigator actions must therefore be documented.

### Remote collection benefits from preparation

Organizations that deploy and validate EDR, DFIR agents, logging, and remote
response capabilities before an incident can investigate more efficiently.

### Windows remote administration is operationally diverse

RDP, WinRM, and WMI expose different levels of interaction and create different
forensic footprints.

### Persistence should be assessed contextually

A startup entry is not automatically malicious.

Assessment should consider:

- executable path;
- signing or provenance;
- user context;
- persistence location;
- surrounding telemetry;
- file characteristics;
- relationship to the incident timeline.

### Governance remains part of incident response

Authorization, escalation, least privilege, accountability, and customer
coordination are operational security controls, not administrative obstacles.


## Training Provenance

This artifact was independently written after authorized hands-on training in a
TryHackMe laboratory environment.

It does not reproduce room questions, answers, flags, credentials, target
addresses, remote-access secrets, or challenge-specific solution values.

The purpose of this document is to preserve transferable DFIR methodology and
analytical reasoning for defensive cybersecurity practice.

## Current Status

The authorized DFIR training scenario has been completed.

The portfolio artifact documents the transferable investigation methodology and
technical lessons from the full exercise while intentionally excluding lab
credentials, flags, target identifiers, and challenge-specific answer values.
