# DFIR Key Artifacts Matrix

## Purpose

This matrix provides a structured reference for identifying and prioritizing
Windows forensic artifacts during incident response.

It is intended to support rapid triage while preserving the distinction between
observed evidence, analyst interpretation, and conclusions.

## Status

Completed training artifact.

The matrix is being developed from authorized DFIR training and independently
reconstructed for defensive use. It does not reproduce challenge answers,
credentials, flags, or proprietary lab content.

## Collection Principle

Collection should be driven by investigative questions rather than by collecting
everything indiscriminately.

Key questions include:

- What happened?
- When did it happen?
- Which account was involved?
- Which process executed?
- Which files were created, modified, or deleted?
- Was persistence established?
- Was lateral movement performed?
- Were credentials accessed?
- Which network destinations were contacted?
- What evidence may disappear if collection is delayed?

## Artifact Matrix

| Artifact category | Examples | What it may reveal | Volatility / collection concern | Analyst questions |
|---|---|---|---|---|
| Windows Event Logs | Security, System, Application, PowerShell, Defender, Sysmon | Authentication, account activity, process execution, PowerShell activity, persistence indicators, security events | Logs may be cleared, overwritten, disabled, or incomplete | Which users logged in? Which processes executed? Are there authentication anomalies? |
| Application Logs | Web-server logs, application-specific logs, browser history | Web attacks, application exploitation, remote-management activity, user browsing activity | Format and retention vary by application | Was an application exploited? Which client/source interacted with it? |
| Windows Prefetch | `.pf` execution artifacts | Evidence that executables ran, execution frequency, approximate execution timing | Not every execution produces Prefetch evidence; configuration matters | Was the suspected executable actually launched? |
| Windows Registry | SYSTEM, SOFTWARE, SECURITY, SAM, NTUSER.DAT, UsrClass.dat | Persistence, configuration, accounts, user activity, RDP history and system state | Hives may require transaction logs or a consistent export | Was persistence configured? Is there evidence of remote access or configuration change? |
| NTFS Metadata | `$MFT`, `$LogFile`, filesystem metadata, alternate data streams | File existence, modification/deletion activity, timestamps and filesystem history | Evidence can decay as filesystem activity continues | Did a suspicious file exist even if it was later deleted? |
| Host Files | Temporary files, scripts, dumps, attacker tooling, output files | Reconnaissance output, credential-access artifacts, scripts and tooling | Files may be deleted or overwritten | What tools or output did the intruder leave behind? |
| Memory | RAM image, running processes, handles, network state, injected code | Processes, connections, injected code, credentials-related activity and possible C2 configuration | Highly volatile; evidence decreases after process exit and is lost on reboot | What was running? What connections existed? Was code injected? |
| Disk Image | Forensic image such as E01/raw acquisition | Broad filesystem state, deleted files, timelines, persistence and historical activity | Large and expensive to acquire/store at scale | Is deeper historical reconstruction required? |

## Evidence Priority

A useful high-level principle is to collect the most volatile evidence first
when doing so is operationally safe and consistent with the incident-response
procedure.

Example prioritization:

1. Volatile runtime evidence
2. Relevant event and application logs
3. High-value host artifacts
4. Registry and filesystem metadata
5. Targeted file acquisition
6. Full disk acquisition when justified

This is not an absolute order. Incident scope, containment requirements,
business impact, legal requirements and evidence-preservation procedures may
change the sequence.

## Evidence vs. Interpretation

Examples:

**Evidence**

> A process was present in memory.

**Interpretation**

> The process may be associated with malicious activity.

**Conclusion**

> Malicious execution is confirmed only when supported by sufficient correlated
> evidence.

The same discipline should be applied to logins, deleted files, registry
changes and network connections.

## Limitations

No single forensic artifact should normally be treated as a complete account of
an incident.

Potential limitations include:

- log deletion or retention limits;
- incomplete telemetry;
- timestamp interpretation;
- overwritten filesystem metadata;
- volatile-memory loss;
- application-specific logging behavior;
- anti-forensic activity;
- collection performed after containment or reboot;
- legitimate administrative behavior resembling malicious activity.

Correlation across independent evidence sources is therefore preferred.

## Training Provenance

This artifact was developed after hands-on training in an authorized TryHackMe
DFIR environment.

It does not reproduce room questions, flags, answers, challenge solutions,
credentials, target IP addresses, or proprietary laboratory data.

The matrix was independently reconstructed as a defensive reference for SOC and
DFIR practice.
