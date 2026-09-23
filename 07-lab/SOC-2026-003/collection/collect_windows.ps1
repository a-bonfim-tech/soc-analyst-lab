#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][datetimeoffset]$StartUtc,
    [Parameter(Mandatory=$true)][datetimeoffset]$EndUtc,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][ValidateSet('baseline','final')][string]$Phase,
    [Parameter(Mandatory=$true)][switch]$AuthorizedDisposableLab
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows is required.' }
if (-not $AuthorizedDisposableLab) { throw 'Explicit lab authorization is required.' }
if ($StartUtc -ge $EndUtc -or $EndUtc -gt [datetimeoffset]::UtcNow) {
    throw 'Provide a completed UTC window with StartUtc before EndUtc.'
}
if (($EndUtc - $StartUtc).TotalHours -gt 2) { throw 'Limit collection to two hours per package.' }
# Never overwrite an existing package. Keep packages outside a repository/shared folder.
$destination = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $destination) { throw 'Output directory already exists; choose a new path.' }
$parent = Split-Path -Parent $destination
if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'Create the private parent directory first.' }
$null = New-Item -ItemType Directory -Path $destination -ErrorAction Stop
$utf8 = New-Object System.Text.UTF8Encoding($false)
$collectionStarted = [datetimeoffset]::UtcNow
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$elevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) { Write-Warning 'Not elevated: Security export may be unavailable.' }
$sources = @(
    @{ Name='security'; Channel='Security'; Ids=@(4624,4625,4672,4688); Required=$true },
    @{ Name='sysmon'; Channel='Microsoft-Windows-Sysmon/Operational'; Ids=@(1,3,11,12,13,14); Required=$true },
    @{ Name='powershell'; Channel='Microsoft-Windows-PowerShell/Operational'; Ids=@(4103,4104); Required=$false },
    @{ Name='defender'; Channel='Microsoft-Windows-Windows Defender/Operational'; Ids=@(1116,1117); Required=$false }
)
$inventory = @()
foreach ($source in $sources) {
    $entry = [ordered]@{
        name=$source.Name; channel=$source.Channel; event_ids=$source.Ids
        required=$source.Required; status='unavailable'; count=0; file=$null; error_code=$null
    }
    $writer = $null
    $observedIds = @{}
    $path = Join-Path $destination ($source.Name + '.xml')
    try {
        $log = Get-WinEvent -ListLog $source.Channel -ErrorAction Stop
        if (-not $log.IsEnabled) { throw 'ChannelDisabled' }
        $writer = New-Object System.IO.StreamWriter($path, $false, $utf8)
        $writer.WriteLine('<?xml version="1.0" encoding="utf-8"?>')
        $writer.WriteLine('<Events>')
        try {
            Get-WinEvent -FilterHashtable @{
                LogName=$source.Channel; Id=$source.Ids
                StartTime=$StartUtc.UtcDateTime; EndTime=$EndUtc.UtcDateTime
            } -Oldest -ErrorAction Stop | ForEach-Object {
                # Preserve the actual EventRecord XML; never synthesize a record.
                $writer.WriteLine($_.ToXml())
                $entry['count'] += 1
                $observedIds[[int]$_.Id] = $true
            }
        } catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
        }
        $writer.WriteLine('</Events>')
        $writer.Dispose()
        $writer = $null
        $entry.file = $source.Name + '.xml'
        $entry.status = if ($entry['count'] -gt 0) { 'collected' } else { 'no_events' }
    } catch {
        if ($null -ne $writer) { $writer.Dispose(); $writer = $null }
        # A partial export is retained as such, never accepted by the importer.
        if (Test-Path -LiteralPath $path) {
            Move-Item -LiteralPath $path -Destination ($path + '.partial') -ErrorAction Stop
            $entry.file = $source.Name + '.xml.partial'
            $entry.status = 'partial'
        }
        $entry.error_code = $_.FullyQualifiedErrorId
        Write-Warning ($source.Name + ': unavailable or incomplete; see metadata.json.')
    }
    $entry['observed_event_ids'] = @($observedIds.Keys | Sort-Object)
    $entry['unobserved_event_ids'] = @($source.Ids | Where-Object { -not $observedIds.ContainsKey([int]$_) })
    if ($entry['unobserved_event_ids'].Count -gt 0) {
        Write-Warning ($source.Name + ': IDs not observed in this export: ' + ($entry['unobserved_event_ids'] -join ',') + '; verify coverage separately.')
    }
    $inventory += [pscustomobject]$entry
}
$ready = @($inventory | Where-Object { $_.required -and $_.status -ne 'collected' }).Count -eq 0
$metadata = [ordered]@{
    schema_version=1; case_id='SOC-2026-003'; phase=$Phase
    source_kind='Windows EventRecord.ToXml'; authorized_disposable_lab=$true
    hostname=$env:COMPUTERNAME; collector=$identity.Name
    os_version=[System.Environment]::OSVersion.VersionString
    powershell_version=$PSVersionTable.PSVersion.ToString(); elevated=$elevated
    local_timezone=[System.TimeZoneInfo]::Local.Id
    requested_start_utc=$StartUtc.ToUniversalTime().ToString('o')
    requested_end_utc=$EndUtc.ToUniversalTime().ToString('o')
    collection_start_utc=$collectionStarted.ToString('o')
    collection_end_utc=[datetimeoffset]::UtcNow.ToString('o')
    collector_script_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    required_sources_collected=$ready; channels=$inventory
    limitations=@('Filtered XML exports, not full EVTX acquisition.',
                  'Channel availability does not prove all relevant audit or Sysmon filters are enabled.',
                  'Raw exports may contain sensitive event data; keep private and review before publication.')
}
[System.IO.File]::WriteAllText((Join-Path $destination 'metadata.json'), ($metadata | ConvertTo-Json -Depth 8), $utf8)
$files = @(Get-ChildItem -LiteralPath $destination -File | Sort-Object Name | ForEach-Object {
    [ordered]@{name=$_.Name; bytes=$_.Length; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
})
$manifest = [ordered]@{schema_version=1; files=$files}
$manifestPath = Join-Path $destination 'manifest.json'
[System.IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 6), $utf8)
$digest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText((Join-Path $destination 'manifest.sha256'), ($digest + "  manifest.json`n"), $utf8)
Write-Output ('Collection package: ' + $destination)
if (-not $ready) { Write-Warning 'Required source missing/empty: do not proceed to conclusions.'; exit 2 }
exit 0
