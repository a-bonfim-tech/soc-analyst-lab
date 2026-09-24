# Windows Registry Hands-on Investigation

## Scenario

This document summarizes a hands-on Windows Registry forensic investigation
performed in an authorized TryHackMe training environment.

The scenario involved a Windows workstation suspected of unauthorized activity.

Available context included:

- multiple local user accounts;
- possible activity involving shared/network-accessible storage;
- external USB-device activity;
- a collected Windows forensic triage dataset.

The goal was to identify and correlate relevant Registry artifacts without
overstating what those artifacts proved.

## Evidence Sources

The investigation used offline Windows forensic artifacts collected under a
triage directory preserving relevant portions of the Windows filesystem.

Primary Registry evidence included:

- `SAM`;
- `SYSTEM`;
- `SOFTWARE`;
- `NTUSER.DAT`;
- `USRCLASS.DAT`;
- `Amcache.hve`.

Associated `NTUSER.DAT` transaction logs were also available.

## Tools

Primary tools used during the investigation:

- Eric Zimmerman's Registry Explorer;
- EZTools;
- KAPE-collected artifacts.

Registry Explorer was the primary analysis interface.

## Methodology

The investigation followed this workflow:

1. load forensic Registry hives rather than inspect the live Registry;
2. replay transaction logs where required;
3. preserve the original evidence;
4. identify relevant Registry artifact families;
5. search for specific filenames or application references;
6. distinguish Registry key metadata from artifact-specific timestamps;
7. correlate findings across independent Registry artifacts;
8. record only validated findings.

For `NTUSER.DAT`, transaction logs were replayed against the forensic/in-memory
representation.

The original hive on disk was not modified.

## Findings

### 1. User Accounts

#### Observation

The SAM hive contained standard Windows accounts together with three
user-created accounts:

- `THM-4n6`
- `thm-user`
- `thm-user2`

#### Interpretation

The collected workstation contained three accounts created beyond the standard
built-in/system account set observed during the exercise.

#### Limitation

Account existence does not establish:

- who created the account;
- whether the account was malicious;
- whether the account logged on;
- what activity the account performed.

#### Finding

**Three user-created accounts were identified.**

---

### 2. Password Hint Artifact

#### Observation

Registry Explorer exposed a `UserPasswordHint` value associated with the
`THM-4n6` account.

Observed value:

`count`

#### Interpretation

The SAM evidence preserved a password-hint value associated with that local
account.

#### Limitation

A password hint:

- is not the user's password;
- does not demonstrate account compromise;
- does not establish whether the account was used.

#### Finding

A password-hint artifact was recovered for `THM-4n6`.

---

### 3. `ChangeLog.txt` Activity

#### Observation

Registry Explorer searches identified references to:

`ChangeLog.txt`

Observed path:

`C:\Users\THM-4n6\Desktop\KAPE\KAPE\ChangeLog.txt`

The validated activity timestamp associated with the exercise was:

`2021-11-24 18:18:48`

During analysis, a Registry key Last Write timestamp of:

`2021-11-24 18:24:49`

was also visible.

#### Interpretation

The relevant forensic artifact supported activity involving `ChangeLog.txt` at
`2021-11-24 18:18:48`.

The separate `18:24:49` value represented modification of the Registry key, not
the requested file-activity timestamp.

#### Limitation

A Registry key's Last Write timestamp must not automatically be substituted for
the timestamp encoded or represented by the forensic artifact stored beneath
that key.

The Registry evidence also does not independently establish that the complete
contents of the file were read.

#### Finding

Relevant `ChangeLog.txt` activity was identified at:

**2021-11-24 18:18:48**

---

### 4. Python Installer Path Evidence

#### Observation

A Registry Explorer search for:

`python-3.8.2`

returned evidence referencing:

`\\vmware-host\Shared Folders\setups\python-3.8.2.exe`

The same shared location was mapped on the Windows system as:

`Z:\setups\python-3.8.2.exe`

#### Interpretation

The forensic evidence associated the Python 3.8.2 installer with a VMware
shared-folder location exposed to Windows through drive `Z:`.

#### Limitation

The UNC representation and the mapped drive representation describe the same
underlying shared location but should not be treated as different independent
events.

The Registry reference should also be interpreted together with execution
artifacts before making broader conclusions about program behavior.

#### Finding

The validated Windows path associated with the installer was:

**`Z:\setups\python-3.8.2.exe`**

Underlying shared-folder representation:

**`\\vmware-host\Shared Folders\setups\python-3.8.2.exe`**

---

### 5. USB Device Activity

#### Observation

USB Registry artifacts identified a device with the friendly name:

`USB`

Connection metadata indicated a last-connection timestamp of:

`2021-11-24 18:40:06`

The relevant property semantics studied during the exercise included:

- `0064` — first connection;
- `0066` — last connection;
- `0067` — last removal.

#### Interpretation

The Registry evidence supported that the device represented by the friendly
name `USB` was last connected at the validated timestamp.

#### Limitation

The evidence does not independently establish:

- which files were accessed;
- whether files were copied;
- whether the device was used maliciously;
- who physically connected the device.

A friendly name is also not necessarily a globally unique hardware identifier.

No unverified USB serial number is included in this documentation.

#### Finding

The USB device with friendly name `USB` was last connected at:

**2021-11-24 18:40:06**

---

### 6. File Explorer Execution Evidence

#### Observation

UserAssist contained an entry for File Explorer with:

- Run Count: `26`
- Last Executed: `2021-12-01 13:02:43`

#### Interpretation

The UserAssist artifact supported repeated GUI/Explorer-mediated File Explorer
execution activity for the associated user context.

#### Limitation

UserAssist is not a complete record of all process execution mechanisms.

The Run Count should be interpreted according to UserAssist semantics and not
generalized into unrelated user actions.

#### Finding

File Explorer had a validated UserAssist Run Count of:

**26**

with the observed last execution timestamp:

**2021-12-01 13:02:43**

## Timeline

| Timestamp | Artifact / Event | Evidence |
|---|---|---|
| `2021-11-24 18:18:48` | `ChangeLog.txt` relevant activity | User Registry artifact |
| `2021-11-24 18:40:06` | USB device `USB` last connected | USB Registry metadata |
| `2021-12-01 13:02:43` | File Explorer last execution observed | UserAssist |

Only validated activity timestamps are included.

The separate Registry key Last Write timestamp associated with the
`ChangeLog.txt` search is intentionally excluded from the event timeline because
it represents a different forensic concept.

## Artifact Correlation

The investigation demonstrated that Registry findings become more useful when
interpreted together rather than in isolation.

Examples include:

### Account context

`SAM`
→ identifies local-account records
→ provides context for user-specific artifacts.

### File activity

Filename/path reference
→ MRU or user-activity artifact
→ artifact-specific timestamp
→ contextual interpretation.

### Program activity

Registry search result
→ mapped/UNC path
→ UserAssist / AppCompatCache / AmCache / BAM-DAM context where available
→ execution assessment.

### External devices

`USBSTOR`
→ device information
→ connection properties
→ Portable Devices friendly name
→ device-activity timeline.

## Important Timestamp Lesson

A central lesson from the practical challenge was:

**Registry key Last Write time is not automatically the event timestamp.**

In the `ChangeLog.txt` analysis:

- artifact-relevant activity: `2021-11-24 18:18:48`;
- Registry key Last Write: `2021-11-24 18:24:49`.

These timestamps represent different forensic facts.

Replacing one with the other would produce an incorrect timeline.

## Search Workflow

Registry Explorer's `Find` functionality was used to locate evidence including:

- `ChangeLog.txt`;
- `python-3.8.2`.

Search scopes included:

- Key name;
- Value name;
- Value data.

Multiple search hits could appear when both the original/replayed evidence
representation and a clean copy of the same hive were loaded.

Those duplicate representations must not be counted as independent user events.

## Limitations

This investigation used a controlled training dataset.

The findings do not establish:

- real-world compromise;
- malware attribution;
- threat-actor attribution;
- complete user activity;
- complete process execution history;
- file-copy activity to or from USB;
- the unresolved USB serial number;
- the identity of an account that never logged in where that value was not
  independently preserved in the available evidence.

No unsupported values were added to this report.

## Lessons Learned

1. Registry artifacts must be interpreted according to their individual
   forensic semantics.
2. Registry key Last Write timestamps and artifact-specific timestamps are not
   interchangeable.
3. A single Registry artifact should rarely be treated as conclusive.
4. Offline hive analysis helps preserve source evidence.
5. Transaction logs can recover relevant Registry state without altering the
   original hive.
6. Duplicate search results from multiple representations of the same evidence
   should not be counted as separate events.
7. Mapped-drive and UNC paths may represent the same underlying location.
8. USB Registry evidence can reconstruct connection history without proving
   what data was transferred.
9. Execution artifacts differ in scope and evidentiary strength.
10. Findings should explicitly separate observation, interpretation and
    limitation.

## Training Provenance

This report was independently written from evidence examined during authorized
hands-on Windows Registry forensic training.

It is structured as a DFIR portfolio case study and intentionally avoids a
question-and-answer or challenge-solution format.

Transient lab infrastructure, disposable credentials, unsupported values and
unverified device identifiers are excluded.
