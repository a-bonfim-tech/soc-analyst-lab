# Windows Forensics 1 — Registry Forensics

## Overview

This case study documents hands-on Windows Registry forensic analysis completed
in an authorized TryHackMe laboratory.

The work focused on offline registry analysis, Windows user-activity artifacts,
execution-related artifacts, USB/device history, timestamp interpretation and
evidence correlation.

The documentation is written as a DFIR portfolio artifact rather than as a
TryHackMe answer sheet.

## Training Context

- Platform: TryHackMe
- Room: Windows Forensics 1
- Topic: Introduction to Windows Registry Forensics
- Discipline: Digital Forensics and Incident Response (DFIR)
- Documented completion state: 96%
- Practical challenge: completed
- Final resource-review action: not confirmed in the captured evidence

This repository does not claim professional incident-response employment based
on this exercise.

## Objectives

The exercise developed practical familiarity with:

- offline Windows Registry hive analysis;
- registry transaction-log replay;
- Windows system and account artifacts;
- user file and folder activity;
- program-execution artifacts;
- USB and external-device history;
- forensic timestamp interpretation;
- artifact correlation;
- evidence-preserving analysis workflows.

## Environment

The practical challenge used a Windows forensic triage collection preserving
relevant portions of the Windows filesystem hierarchy.

Primary evidence sources included:

- `SYSTEM`
- `SOFTWARE`
- `SAM`
- `SECURITY`
- `NTUSER.DAT`
- `USRCLASS.DAT`
- `Amcache.hve`

The investigation was performed against collected forensic artifacts rather
than by modifying the live Registry.

## Tools

Tools used or introduced during the exercise included:

- Eric Zimmerman's Registry Explorer
- EZTools
- KAPE
- RegRipper
- AppCompatCacheParser
- Autopsy

Registry Explorer was the primary GUI analysis tool during the practical
challenge.

## Evidence Handling

A key workflow lesson involved dirty registry hives.

When Registry Explorer identified that `NTUSER.DAT` required transaction-log
replay, the associated logs were used:

- `ntuser.dat.LOG1`
- `ntuser.dat.LOG2`

The transaction logs were replayed against the in-memory/forensic
representation.

The original hive on disk was not modified.

This reinforces the principle:

> Preserve source evidence and perform reconstruction or recovery against
> forensic copies or controlled representations whenever possible.

## Registry Artifact Categories

The investigation covered several categories of Registry evidence.

### System and account information

Examples include:

- operating-system version;
- current control set;
- computer name;
- timezone;
- network-interface history;
- autorun locations;
- local account information from the SAM hive.

### File and folder interaction

Artifacts included:

- RecentDocs;
- Microsoft Office MRUs;
- ShellBags;
- OpenSavePIDlMRU;
- LastVisitedPidlMRU;
- TypedPaths;
- WordWheelQuery.

These artifacts can support reconstruction of user interaction but must not be
overstated as proof that specific file contents were read.

### Evidence of execution

Artifacts studied included:

- UserAssist;
- ShimCache / AppCompatCache;
- AmCache;
- BAM / DAM.

These artifacts have different forensic semantics and should be interpreted
according to Windows version and surrounding evidence.

### External devices

USB analysis included:

- `SYSTEM\CurrentControlSet\Enum\USBSTOR`
- `SYSTEM\CurrentControlSet\Enum\USB`
- `SOFTWARE\Microsoft\Windows Portable Devices\Devices`

Connection metadata included properties representing:

- first connection;
- last connection;
- last removal.

## Practical Investigation

The hands-on challenge used collected Windows Registry evidence to reconstruct
user and device activity.

Validated findings included:

- three user-created accounts;
- a password-hint artifact associated with one user account;
- relevant activity involving `ChangeLog.txt`;
- evidence related to execution of a Python installer from a mapped shared
  location;
- USB device connection history;
- File Explorer execution evidence in UserAssist.

The detailed methodology and validated findings are documented in
[`hands-on-challenge.md`](hands-on-challenge.md).

## Key Forensic Lesson

One of the most important findings from the exercise was the distinction between
a Registry key's Last Write timestamp and the timestamp represented by a
specific forensic artifact.

For the `ChangeLog.txt` investigation, the relevant validated activity timestamp
was not the same as the Registry key Last Write time.

Therefore:

> A Registry key Last Write timestamp must not automatically be treated as the
> timestamp of the user or system activity represented by the artifact.

## Forensic Interpretation Principles

Throughout the documentation, findings are separated into:

1. observation;
2. interpretation;
3. limitation.

Examples:

- ShellBag evidence can support that a directory structure was navigated, but
  does not independently prove that file contents were read.
- ShimCache presence should not automatically be treated as definitive proof of
  execution.
- Registry key Last Write timestamps represent key modification and must not be
  substituted for artifact-specific activity timestamps.

## Skills Demonstrated

This exercise provides evidence of hands-on practice in:

- Windows Registry analysis;
- Windows forensic triage;
- offline hive analysis;
- transaction-log replay;
- artifact identification;
- user-activity reconstruction;
- execution-evidence analysis;
- USB/device forensics;
- timestamp interpretation;
- evidence correlation;
- forensic documentation.

## Supporting Documentation

- [`registry-artifacts.md`](registry-artifacts.md) — concise artifact reference
  with forensic value and limitations.
- [`hands-on-challenge.md`](hands-on-challenge.md) — practical investigation,
  timeline, findings and limitations.

## Limitations

This was an authorized training environment.

The documentation does not establish:

- professional production DFIR experience;
- malware attribution;
- compromise attribution;
- complete endpoint reconstruction;
- exhaustive Windows execution history;
- a verified USB serial number where the training evidence was unresolved.

Only evidence validated during the exercise is used in the investigation
documentation.

## References

Primary references used during the exercise:

- TryHackMe — Windows Forensics 1
- Eric Zimmerman tools / Registry Explorer
- Windows Registry artifacts examined during the authorized lab
