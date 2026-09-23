# SOC-2026-004 — synthetic evidence

These deterministic fixtures were independently authored, not collected from Windows,
a customer or a training room. No commands were executed to generate them. All IPs
are documentation-only TEST-NET addresses. No real incident or malware is represented.

13 Security records and 10 Sysmon records span 2026-09-23 08:00–09:07 UTC.
Fixtures include routine service logons, an approved admin source, user logons,
ordinary PowerShell, Office-parent PowerShell without encoding, encoded maintenance
without an Office parent, an ordinary Run value and an unrelated registry value.

## Schema contract

Security CSV: UTF-8 header, EventID and LogonType are decimal strings; other fields
are strings. TimeGenerated is timezone-aware ISO 8601. RecordId is a unique local
evidence identifier, not a native Windows EventRecordID. Account is normalized
DOMAIN\user; Computer is hostname. 4624 TargetLogonId and 4672 SubjectLogonId are
session identifiers on that computer. PrivilegeList contains assigned privileges,
not proof of privilege use. Empty fields mean not applicable/unavailable.
SubjectUserName is populated for 4672; TargetUserName for 4624/4625. ProcessName is
the logon process context, not the newly executed Sysmon Image.

Sysmon JSON: array of flattened event objects. EventID is an integer; other values
are strings except DestinationPort (integer when present, otherwise empty string).
UtcTime uses explicit UTC. Image, ParentImage and CommandLine describe process
creation (1); DestinationIp/Port describe connection (3); TargetObject/Details and
EventType=SetValue describe registry value setting (13). ProcessGuid is a synthetic
process identity; LogonId is present on creation events and relates to Security
sessions. ParentImage alone cannot prove document execution or initial access.

Asset context JSON: synthetic=true, hostname, asset_type, owner_team, environment,
criticality, expected_admin_sources and privileged_accounts (arrays), normal_patterns,
authorization_status and notes. Admin membership and approved source are contextual
inputs, not native fields in Security events.

## Evidence to reasoning

| Evidence | Supports | Does not establish |
|---|---|---|
| SEC-006–010 | Failure sequence, remote interactive success, assigned special privileges | Brute force, stolen credentials, privilege escalation |
| SYS-005 | Office-parent encoded PowerShell in session 0x900 | Malware or a malicious document |
| SYS-006 | Same process connects to a documentation address on port 443 | C2, TLS payload or exfiltration |
| SYS-007 | Same process sets Run value to public-directory executable | File existence, execution at next logon, malicious intent |

SYS-005's encoded command is UTF-16LE Base64 representing a synthetic script that
prints a marker, tests port 443 at the documentation address and sets the LabUpdater
Run value. It was never executed. The command text is consistent with SYS-006/007,
but process creation records intent, not independent proof that each statement ran.
SYS-009's maintenance command decodes to `Write-Output 'synthetic'`.
No executable or malware payload is supplied. Decode as text only; do not execute
fixture commands on a workstation.

## Reproduce

From the repository root, use the commands in the
[case validation guide](../../07-lab/detection-tests/SOC-2026-004/README.md).
[Investigation](../../03-investigations/SOC-2026-004/investigation.md) and
[coverage](../../04-detection-rules/ATTACK-COVERAGE.md) explain the interpretation.
