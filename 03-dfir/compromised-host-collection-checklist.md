# Compromised Windows Host — DFIR Collection Checklist

## Purpose

Provide a repeatable checklist for collecting high-value forensic evidence from
a suspected compromised Windows endpoint.

This checklist supports triage and evidence preservation. It is not a substitute
for an organization's incident-response, legal, privacy, or chain-of-custody
requirements.

## Status

Completed training artifact.

## 1. Before Collection

- [ ] Confirm incident/case identifier.
- [ ] Record hostname.
- [ ] Record known IP addresses.
- [ ] Record current date, time and timezone.
- [ ] Record analyst identity.
- [ ] Record why the host is being investigated.
- [ ] Determine whether the system is still running.
- [ ] Determine whether the suspected attacker may still be active.
- [ ] Avoid unnecessary interaction with the host.
- [ ] Determine whether containment has already occurred.
- [ ] Record any action that may alter evidence.
- [ ] Confirm approved evidence-storage location.

## 2. Volatile Evidence

Evaluate collection before shutdown or reboot.

- [ ] Running processes.
- [ ] Process parent/child relationships.
- [ ] Logged-on users.
- [ ] Active network connections.
- [ ] Listening ports.
- [ ] Relevant handles or runtime information.
- [ ] System time and timezone.
- [ ] Memory acquisition, when justified and authorized.

### Analyst questions

- What is running now?
- Which user context owns each suspicious process?
- Which remote systems are currently connected?
- Could a reboot destroy important evidence?

## 3. Windows Event Logs

Prioritize channels relevant to the incident.

- [ ] Security.
- [ ] System.
- [ ] Application.
- [ ] PowerShell.
- [ ] Microsoft Defender.
- [ ] Sysmon, if deployed.
- [ ] Other application- or role-specific channels.

### Analyst questions

- Were there successful or failed logons?
- Were accounts created, modified, or elevated?
- Was PowerShell used?
- Were services or scheduled tasks modified?
- Did endpoint protection detect or block anything?
- Are there gaps suggesting log clearing or disabled telemetry?

## 4. Application Evidence

Identify applications relevant to the suspected intrusion path.

- [ ] Web-server logs.
- [ ] Application-specific logs.
- [ ] Remote-management logs.
- [ ] Browser history where relevant and authorized.
- [ ] Application configuration related to the incident.

### Analyst questions

- Was the application an initial-access vector?
- Which source interacted with the service?
- Is exploitation visible before host-level activity?

## 5. Windows OS Artifacts

### Prefetch

- [ ] Identify relevant Prefetch artifacts.
- [ ] Record executable name.
- [ ] Record execution count where available.
- [ ] Record relevant execution timestamps.

### Registry

Consider relevant system and user hives:

- [ ] SYSTEM.
- [ ] SOFTWARE.
- [ ] SECURITY.
- [ ] SAM.
- [ ] NTUSER.DAT.
- [ ] UsrClass.dat.
- [ ] Associated transaction logs when required.

Investigate for:

- [ ] Persistence mechanisms.
- [ ] Autostart entries.
- [ ] User activity.
- [ ] Remote-access history.
- [ ] Security-relevant configuration changes.

## 6. NTFS and File-System Evidence

- [ ] Preserve relevant filesystem metadata.
- [ ] Review `$MFT` where appropriate.
- [ ] Review relevant transaction/log metadata.
- [ ] Identify suspicious files.
- [ ] Identify deleted-file evidence.
- [ ] Review temporary directories where relevant.
- [ ] Look for scripts, dumps and attacker output.
- [ ] Consider alternate data streams where relevant.

### Analyst questions

- Did suspicious tooling exist?
- Was it executed and later deleted?
- Were credential dumps created?
- Were reconnaissance results written to disk?
- Do filesystem timestamps support the investigation timeline?

## 7. Memory Forensics

When a memory image is available:

- [ ] Identify running and recently terminated processes.
- [ ] Construct process relationships.
- [ ] Review network activity.
- [ ] Investigate suspicious process injection.
- [ ] Search for relevant command-and-control indicators.
- [ ] Correlate memory findings with disk and event-log evidence.

### Important limitation

Memory is highly volatile. Evidence may degrade after process termination and is
lost after reboot.

## 8. Disk Acquisition

Consider targeted or full-disk acquisition based on incident scope.

- [ ] Document acquisition method.
- [ ] Record source device.
- [ ] Record destination/evidence identifier.
- [ ] Record acquisition time.
- [ ] Preserve integrity information according to the applicable procedure.
- [ ] Analyze through an approved forensic workflow.

A full disk image may be justified when targeted triage is insufficient for
reconstructing historical activity.

## 9. Evidence Handling

For every collected item record, where applicable:

- [ ] Case ID.
- [ ] Source host.
- [ ] Artifact type.
- [ ] Original path/source.
- [ ] Collection timestamp.
- [ ] Analyst/collector.
- [ ] Collection method/tool.
- [ ] Hash/integrity value.
- [ ] Storage location.
- [ ] Relevant notes.

## 10. Correlation

Do not interpret artifacts in isolation.

Correlate, where available:

```text
Event Logs
    +
Application Logs
    +
Registry / Prefetch
    +
NTFS Metadata
    +
Memory
    +
Disk
    ↓
Incident Timeline
    ↓
Evidence-Based Assessment
```

## 11. Minimum Investigation Output

A completed investigation should attempt to establish:

- Initial access or earliest confirmed malicious activity.
- Accounts involved.
- Processes and tooling involved.
- Privilege changes.
- Persistence.
- Credential-access activity.
- Lateral movement.
- Network communication.
- Files created, modified or deleted.
- Scope of affected assets.
- Remaining evidence gaps.
- Confidence level of major conclusions.

## Training Provenance

This checklist was developed after hands-on training in an authorized TryHackMe
DFIR environment.

It does not reproduce room questions, flags, answers, challenge solutions,
credentials, target IP addresses, or proprietary laboratory data.

The checklist is an independently reconstructed defensive workflow intended for
SOC and DFIR practice.
