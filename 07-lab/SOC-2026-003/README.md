# SOC-2026-003 — operator collection package

**COMPLETED CONTROLLED WINDOWS COLLECTION.** The procedure below documents the
collection workflow used for the authorized disposable Windows laboratory exercise.

Public recruiter-safe outputs are available in the
[Windows endpoint investigation](../../03-investigations/SOC-2026-003/investigation.md)
and the
[sanitized derived correlation artifact](../../10-evidence/SOC-2026-003/windows-endpoint-correlation.md).
Raw endpoint exports remain private because they contain endpoint-specific identifiers.

The [lab plan](lab-plan.md) and
[evidence contract](collection/evidence-contract.md) document the collection design.

## Prerequisites

Disposable authorized Windows 11 ARM64 VM; lab-only identities; UTM snapshot and
clock/timezone noted privately; Windows PowerShell 5.1; operator elevation to read
Security; Security auditing and Sysmon already configured by the operator to capture
the required families. Review the contract's optional channels and limitations.
No installation or audit-policy changes are made by these scripts. If organizational
execution policy blocks scripts, follow the approved policy process; do not bypass it.

Copy the three collection tools and this runbook into the VM from the reviewed
checkout. The commands below assume the package is in the current directory
(`07-lab/SOC-2026-003`). Raw output goes to a new directory under the local lab user's
profile, outside Git/shared folders. Restrict access using the approved evidence
storage policy. Do not use a personal or production endpoint.

## A — preflight and baseline

In an elevated Windows PowerShell session, first run the built-in parser. This is
required because no PowerShell runtime was available on the preparation workstation.
If errors are printed, stop and report them; do not run the scripts.

```powershell
foreach ($script in @('.\collection\collect_windows.ps1', '.\collection\activity.ps1')) {
    $tokens = $null; $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        (Resolve-Path $script).Path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { $parseErrors; throw 'PowerShell parse failed' }
}
$root = Join-Path $env:USERPROFILE ('SOC003-private-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
$baselineEnd = [datetimeoffset]::UtcNow
& .\collection\collect_windows.ps1 -AuthorizedDisposableLab -Phase baseline `
    -StartUtc $baselineEnd.AddMinutes(-2) -EndUtc $baselineEnd `
    -OutputDirectory (Join-Path $root 'baseline')
$LASTEXITCODE
```

Exit 0: required channels exported nonempty results, not confirmation of every
expected event family. Exit 2: required channel unavailable/empty; inspect
metadata.json. A quiet baseline can legitimately lack records. Other exceptions
mean collection failure; preserve any partial output privately and use a new directory
on retry. Check logging coverage before activity; do not manufacture missing logs.

## B/C — benign and detection-relevant marker activity

Record the VM/snapshot, authorization and action times privately. Keep this same
PowerShell session open through final collection. Do not log passwords or secrets.

```powershell
$activityStart = [datetimeoffset]::UtcNow
& .\collection\activity.ps1 -AuthorizedDisposableLab
# Allow asynchronous event delivery before closing the collection window.
Start-Sleep -Seconds 10
$activityEnd = [datetimeoffset]::UtcNow
```

| Activity / purpose | Expected source/family if enabled | Cleanup | Safety boundary |
|---|---|---|---|
| Ordinary child PowerShell; benign process baseline | Security 4688, Sysmon 1; possibly 4103/4104 | Child exits | Marker output only |
| Encoded PowerShell; detection-relevant command-line form | Security 4688, Sysmon 1, possibly 4104 | Child exits | Decoded payload only writes a console marker; not malware |
| Unique HKCU sandbox registry value; observe registry telemetry | Sysmon 12/13/14 if filters include this path | finally removes only the unique key | Not a Run/autostart key; proves no persistence |
| Unique temporary text file; file telemetry | Sysmon 11 if configured | finally deletes exact file | No existing file touched |

Expected events are not observed events. Registry filters often omit non-autostart
keys: record that gap instead of changing filters during collection. This minimal
safe activity does not guarantee the full eventual case narrative or a positive
production detection. Do not substitute SOC-2026-004 fixtures.

Optional authentication extension: use only a dedicated lab account and an approved
operator procedure with known lockout limits. A normal interactive sign-in may
produce Security 4624 (and 4672 if privileges assigned). Do not script credentials
or intentional failure bursts here. Record timing in a new bounded collection window
if signing out would end this session. No account changes or cleanup are required
beyond signing out of the test session. Authentication absence remains a gap.

Optional controlled-network extension is deferred: no remote destination, listener
or network traffic is created automatically. Sysmon 3 may be absent. Do not assume
localhost events are logged by the installed filters. No malicious ancestry,
persistence or network behavior is claimed by these marker activities.

## D — final collection

```powershell
& .\collection\collect_windows.ps1 -AuthorizedDisposableLab -Phase final `
    -StartUtc $activityStart -EndUtc $activityEnd `
    -OutputDirectory (Join-Path $root 'final')
$LASTEXITCODE
Get-Content -LiteralPath (Join-Path $root 'final\metadata.json')
```

Each baseline/final package contains metadata.json, manifest.json, manifest.sha256,
and security.xml, sysmon.xml, powershell.xml, defender.xml for queryable channels.
Empty queried channels produce an empty Events wrapper with status no_events;
unavailable channels produce no XML; caught export failures retain *.xml.partial.
A forced process termination or VM crash may leave an unfinished XML/package without
a manifest; such a package must not be ingested as a successful collection.
Inventory records every source/status/count/error code, observed event IDs and
unobserved selected IDs. Unobserved IDs are coverage limitations to investigate,
not proof of disabled logging or a requirement to manufacture activity. Exit 0
still means nonempty required sources, not every selected ID observed. All retained files except
the manifest and its checksum are covered by the manifest. Do not edit partial files
into valid evidence. Required source gaps prevent collection readiness.

## Recollection after temporal-filter correction

Do not rerun activity.ps1, replace the original activity or use a new activity window.
Deploy only the corrected collector, perform the parser preflight, and preserve the
failed package. Read the ORIGINAL activity_start_utc and activity_end_utc from the
private preserved JSON activity-window record. Never infer them from this example,
current time, the event examples or a new execution. In this package directory:

```powershell
$windowPath = Read-Host 'Path to the preserved activity-window JSON record'
$window = Get-Content -Raw -LiteralPath $windowPath | ConvertFrom-Json
foreach ($value in @($window.activity_start_utc, $window.activity_end_utc)) {
    if ([string]::IsNullOrWhiteSpace($value) -or $value -notmatch '(Z|[+-]\d{2}:\d{2})$') {
        throw 'Original timestamp with explicit offset required; do not reconstruct it'
    }
}
$activityStart = [datetimeoffset]::Parse($window.activity_start_utc, [cultureinfo]::InvariantCulture)
$activityEnd = [datetimeoffset]::Parse($window.activity_end_utc, [cultureinfo]::InvariantCulture)
$destination = Join-Path (Split-Path -Parent $windowPath) ('final-recollect-' + [guid]::NewGuid().ToString('N'))
& .\collection\collect_windows.ps1 -AuthorizedDisposableLab -Phase final `
    -StartUtc $activityStart -EndUtc $activityEnd -OutputDirectory $destination
$LASTEXITCODE
```

The new directory contains a recollection of existing endpoint logs, not newly
executed activity. Missing records may reflect retention or query/collection issues;
an empty package alone does not prove no telemetry exists. Defender remains optional.

Temporal diagnosis: the old filter passed DateTimeOffset.UtcDateTime (Kind=Utc).
The published Get-WinEvent implementation calls ToString, DateTime.Parse and then
ToUniversalTime, allowing UTC wall time to be reinterpreted as local time. At UTC+02
this queries two hours earlier. Its formatter also limits fractional precision.
The corrected collector supplies an inclusive UTC SystemTime XPath with seven
fractional digits, bypassing that path entirely. Merely passing LocalDateTime would
address the wall-clock mismatch but not preserve the original fractional bounds.
Metadata and native event timestamps remain unchanged.

[Microsoft's legacy query builder source](https://github.com/PowerShell/PowerShell/blob/v6.0.0-alpha.9/src/Microsoft.PowerShell.Commands.Diagnostics/GetEventCommand.cs)
provides the conversion path. Local regression tests model it and check the collector
source template; they do not execute the Windows 5.1 binary or native event query.
The exact endpoint runtime result must be verified by recollection. No real telemetry
was generated, copied into tests or collected by this correction.

## E — cleanup

activity.ps1 uses finally cleanup. If interrupted or the VM crashes, use its printed
exact cleanup targets to inspect and remove only that unique SOC003 temporary file
and SOCAnalystLab-GUID HKCU key. Do not use broad wildcard deletion. No autostart was
created; never represent these registry markers as successful persistence. Preserve
collection packages and operator notes before reverting the disposable VM snapshot.

## F — transfer and ingestion (after real collection)

Transfer privately using an approved encrypted/local channel; verify checksums on
arrival. Do not commit raw exports. On a workstation with Python 3.10+, run:

```text
python3 -B 07-lab/SOC-2026-003/collection/ingest_windows.py --input /PRIVATE/PATH/final --output /PRIVATE/PATH/final-derived
```

Replace the two private paths with actual locations. A new derived directory contains
events.jsonl and ingestion.json; source files remain unchanged. Exit 0: package
verified and required sources nonempty; exit 2: available events normalized but a
required source is missing; exit 1: invalid package/input or filesystem error.
Never overwrite an existing output directory. Failed writes may leave an incomplete
derived directory; retain it for troubleshooting and choose a new path on retry.

Integrity/schema checks cannot authenticate a manufactured package. Operator review
of endpoint provenance remains mandatory. No analysis or case-completion claim follows
a successful import. EventData absence becomes null, not invented values; original
XML and original timestamp strings remain the source of truth.

## Local validation

```text
python3 -B -m unittest discover -s 07-lab/SOC-2026-003/collection -p 'test_*.py' -v
```

Tests create temporary, explicitly artificial XML packages solely to exercise parser
behavior. They are never collected evidence. No Windows runtime execution is claimed.
Current main has been incorporated without rewriting the historical commits. Run
`python3 -B 06-scripts/validate_portfolio.py` from the repository root using the
existing validation environment. This does not replace the Windows parser preflight.

## Command references

- [Microsoft Get-WinEvent filtering](https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable)
- [Microsoft Windows PowerShell encoded command](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1)
