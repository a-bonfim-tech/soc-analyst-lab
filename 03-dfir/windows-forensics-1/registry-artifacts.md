# Windows Registry Forensic Artifact Reference

## Purpose

This reference summarizes Windows Registry artifacts examined during authorized
hands-on forensic training.

It is intended as a practical DFIR reference rather than a complete Windows
Registry specification.

For every artifact, distinguish:

- what was directly observed;
- what the artifact can reasonably support;
- what the artifact cannot prove by itself.

## Evidence Handling Principle

Registry analysis should preferably be performed against forensic copies rather
than by modifying live evidence.

When a hive requires transaction-log replay, associated transaction logs should
be applied to a forensic copy or controlled in-memory representation.

In the training exercise, Registry Explorer replayed:

- `ntuser.dat.LOG1`
- `ntuser.dat.LOG2`

against `NTUSER.DAT`.

The original hive on disk was not modified.

## Core Registry Hives

| Hive | Typical forensic role |
|---|---|
| `SYSTEM` | System configuration, control sets, services, network and device information |
| `SOFTWARE` | Operating-system/application configuration and machine-wide software artifacts |
| `SAM` | Local account information |
| `SECURITY` | Security-related configuration and policy data |
| `NTUSER.DAT` | Per-user activity and configuration |
| `USRCLASS.DAT` | Per-user shell and Explorer artifacts |
| `Amcache.hve` | Application-related metadata including paths, timestamps and hashes |

Typical offline system hive location:

`C:\Windows\System32\config\`

Typical per-user hive location:

`C:\Users\<username>\NTUSER.DAT`

---

## System Information and Accounts

| Category | Artifact | Registry/Hive Path | Forensic Value | Limitation |
|---|---|---|---|---|
| Operating system | Windows version | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` | Identifies Windows version/build-related information | Does not describe user activity |
| Control set | Current control set selection | `SYSTEM\Select\Current` | Identifies which control set should be interpreted as current | Numeric value must be resolved to the corresponding control set |
| Control set | Last known good | `SYSTEM\Select\LastKnownGood` | Identifies the LastKnownGood control set | Does not prove that it was actively used during the event under investigation |
| Host identity | Computer name | `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName` | Supports identification of the Windows host | Historical renaming requires additional evidence |
| Time context | Time zone | `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` | Supports timestamp interpretation | Configuration may have changed over time |
| Networking | Interface history/configuration | `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces` | May expose IP configuration and network-interface information | Does not alone prove network communication at a particular time |
| Accounts | Local users | `SAM\Domains\Account\Users` | Identifies local-account records and related account data | Account existence does not prove account use |

## Autorun Locations

| Artifact | Registry/Hive Path | Forensic Value | Limitation |
|---|---|---|---|
| User Run | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run` | Identifies user-context programs configured for automatic launch | Configuration does not prove successful execution |
| User RunOnce | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce` | Identifies one-time user-context startup configuration | Presence does not prove execution |
| Machine Run | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Identifies machine-level autorun configuration | Legitimate software commonly uses this location |
| Machine RunOnce | `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | Identifies one-time machine-level startup configuration | Presence alone is not malicious |
| Explorer policy Run | `SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run` | May identify programs configured to start through Explorer policy | Requires context and corroboration |

Autorun entries should be treated as persistence/configuration evidence, not as
standalone proof that the referenced executable actually ran.

---

## File and Folder Activity

### RecentDocs

Path:

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

Extension-specific subkeys may also exist, for example:

`RecentDocs\.pdf`

**Forensic value**

Supports evidence that an account had recent interaction with or knowledge of
files.

MRU ordering can help reconstruct user activity.

**Limitation**

Presence does not independently prove that the file contents were read.

---

### Microsoft Office MRUs

Artifact family:

`NTUSER.DAT\Software\Microsoft\Office\VERSION`

Newer/user-specific structures may include:

`NTUSER.DAT\Software\Microsoft\Office\VERSION\UserMRU\LiveID_####\FileMRU`

**Forensic value**

Can identify Office documents recently used by the account.

**Limitation**

Interpretation depends on Office version and the specific MRU structure.

---

### ShellBags

Relevant paths include:

`USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`

`USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

`NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`

`NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`

**Forensic value**

Can provide evidence that an account interacted with or navigated directory
structures, including directories that may no longer exist.

**Limitation**

ShellBag evidence does not independently prove that any specific file's contents
were opened or read.

---

### OpenSavePIDlMRU

Path:

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU`

**Forensic value**

Can preserve file/location interaction associated with Windows Open/Save dialogs.

**Limitation**

The artifact should be interpreted in the context of the application and MRU
ordering.

---

### LastVisitedPidlMRU

Path:

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`

**Forensic value**

Can associate an executable/application with a directory used through a Windows
Open/Save dialog.

**Limitation**

It should not automatically be interpreted as proof that every file in the
directory was opened.

---

### TypedPaths

Path:

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`

**Forensic value**

Can identify paths manually entered into Windows Explorer.

**Limitation**

Typed text does not by itself establish the full activity that followed.

---

### WordWheelQuery

Path:

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`

**Forensic value**

Can preserve Windows Explorer search terms.

**Limitation**

A search term is evidence of search activity, not proof that a resulting file
was opened.

---

## Evidence of Execution

### UserAssist

Path:

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

**Forensic value**

Can provide GUI/Explorer-mediated program-execution information including
execution counts and timestamps.

**Limitation**

UserAssist is not an exhaustive record of every possible execution method.

Command-line, service, scheduled or other execution mechanisms may not be
represented in the same way.

---

### ShimCache / AppCompatCache

Path:

`SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`

Also known as:

- ShimCache
- Application Compatibility Cache
- AppCompatCache

**Forensic value**

Provides application compatibility metadata that can contribute to execution
analysis and historical program presence.

**Limitation**

The presence of an entry must not automatically be treated as definitive proof
of execution.

Semantics vary across Windows versions and require contextual interpretation.

---

### AmCache

Hive:

`C:\Windows\appcompat\Programs\Amcache.hve`

Artifact path studied:

`Amcache.hve\Root\File\{Volume GUID}\`

**Forensic value**

Can preserve application-related metadata such as:

- file paths;
- timestamps;
- SHA1 hashes.

**Limitation**

AmCache should not be treated as standalone proof of execution across all
Windows versions and configurations.

---

### BAM / DAM

Paths:

`SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`

`SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}`

**Forensic value**

Can preserve executable path/activity information associated with a user.

**Limitation**

Interpretation depends on Windows version and should be correlated with other
execution artifacts.

---

## External Devices and USB Forensics

### USBSTOR

Path:

`SYSTEM\CurrentControlSet\Enum\USBSTOR`

**Forensic value**

Identifies USB mass-storage device information such as vendor, product and
device-instance data.

**Limitation**

Device presence alone does not establish what files were accessed or copied.

---

### USB Enumeration

Path:

`SYSTEM\CurrentControlSet\Enum\USB`

**Forensic value**

Provides USB device enumeration information.

**Limitation**

Not every USB device is a storage device.

---

### Connection Metadata

Connection-related properties may appear beneath structures such as:

`SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven_Prod_Version\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####`

Property identifiers studied during the exercise:

| Property | Meaning |
|---|---|
| `0064` | First connection |
| `0066` | Last connection |
| `0067` | Last removal |

**Forensic value**

Supports reconstruction of USB-device connection history.

**Limitation**

Timestamps should be interpreted with device identity, Registry structure and
time-zone context.

---

### Windows Portable Devices

Path:

`SOFTWARE\Microsoft\Windows Portable Devices\Devices`

**Forensic value**

Can expose user-facing device information such as friendly names and volume
information.

**Limitation**

Friendly names are not guaranteed to be globally unique device identifiers.

---

## Timestamp Interpretation

Registry analysis may expose several different timestamp concepts.

These must not be treated as interchangeable.

Examples include:

- Registry key Last Write time;
- artifact-specific activity timestamp;
- device connection timestamp;
- program execution timestamp.

A Registry key Last Write timestamp records modification of that key.

It does not automatically represent the user or system activity encoded in the
artifact.

This distinction was directly relevant during the practical investigation.

---

## Correlation Principle

No single Registry artifact should normally be treated as a complete account of
an event.

Prefer correlation across independent evidence sources such as:

- account records;
- MRUs;
- ShellBags;
- UserAssist;
- ShimCache;
- AmCache;
- BAM/DAM;
- USB metadata;
- filesystem evidence;
- event logs.

The analytical sequence should remain:

**Observation → Interpretation → Limitation → Corroboration → Finding**

---

## Training Provenance

This reference was independently reconstructed after authorized hands-on Windows
Registry forensic training.

It is not a reproduction of TryHackMe questions, answer keys or proprietary
course material.

Challenge-specific answers are intentionally excluded from this reference and
are documented only where necessary as investigation findings in the associated
hands-on case study.
