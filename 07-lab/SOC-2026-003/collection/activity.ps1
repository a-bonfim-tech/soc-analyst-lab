#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][switch]$AuthorizedDisposableLab)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT' -or -not $AuthorizedDisposableLab) {
    throw 'Run only on the authorized disposable Windows lab.'
}
# Unique sandbox; this is NOT an autostart/Run key and establishes no persistence.
$runId = [guid]::NewGuid().ToString('N')
$key = 'HKCU:\Software\SOCAnalystLab-' + $runId
$marker = Join-Path $env:TEMP ('SOC003-' + $runId + '.txt')
if ((Test-Path -LiteralPath $key) -or (Test-Path -LiteralPath $marker)) { throw 'Unexpected existing activity target; stop.' }
Write-Output ('Activity started UTC: ' + [datetimeoffset]::UtcNow.ToString('o'))
Write-Output ('Cleanup targets: ' + $key + ' ; ' + $marker)
try {
    & "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command 'Write-Output "SOC003 benign process marker"'
    if ($LASTEXITCODE -ne 0) { throw 'Benign child PowerShell failed.' }
    $payload = 'Write-Output "SOC003 harmless encoded marker"'
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
    & "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand $encoded
    if ($LASTEXITCODE -ne 0) { throw 'Encoded marker process failed.' }
    $null = New-Item -Path $key -ErrorAction Stop
    $null = New-ItemProperty -LiteralPath $key -Name 'SOC003Marker' -Value 'Benign lab marker; not persistence' -PropertyType String
    Set-Content -LiteralPath $marker -Value 'SOC003 benign lab marker' -Encoding UTF8
    Write-Output 'Marker activities completed; verify actual event availability after export.'
} finally {
    # Attempt both cleanups even if one fails; propagate failure to the operator.
    try {
        if (Test-Path -LiteralPath $key) { Remove-Item -LiteralPath $key -Recurse -ErrorAction Stop }
    } finally {
        try {
            if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -ErrorAction Stop }
        } finally {
            Write-Output ('Activity ended UTC: ' + [datetimeoffset]::UtcNow.ToString('o'))
        }
    }
}
