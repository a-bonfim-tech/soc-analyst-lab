# SOC-2026-003 — Windows Endpoint Telemetry Correlation

## Scope

This artifact documents a controlled Windows endpoint telemetry exercise performed in an authorized disposable lab.

The activity was intentionally benign. Its purpose was to generate observable endpoint behavior and correlate independent Windows telemetry sources without representing the activity as malware or a production incident.

Raw endpoint exports remain private. This public artifact is a sanitized, derived record.

## Evidence provenance

- Case: `SOC-2026-003`
- Environment: authorized disposable Windows lab
- Evidence source: real Windows EventRecord XML exported from the endpoint
- Required sources collected successfully: Windows Security and Sysmon
- Additional source collected: PowerShell Operational
- Microsoft Defender produced no Event IDs 1116/1117 during the activity
- Final collection normalized: 541 source events
- Missing required sources after ingestion: none

The raw collection package was transferred from the Windows VM to the analysis host and its SHA-256 was verified before analysis.

## Correlated activity timeline

| UTC | Source | Event ID | Observation |
|---|---|---:|---|
| 00:49:43.291 | Windows Security | 4688 | PowerShell process created with the benign SOC003 process marker command |
| 00:49:43.313 | Sysmon | 1 | Corresponding PowerShell process creation observed |
| 00:49:44.307 | PowerShell Operational | 4104 | Script block recorded the benign process marker |
| 00:49:45.401 | PowerShell Operational | 4104 | Script block exposed the harmless payload executed through `-EncodedCommand` |
| 00:49:45.649 | Sysmon | 12 | Temporary lab Registry key created |
| 00:49:45.657 | Sysmon | 13 | Temporary `SOC003Marker` Registry value written |
| 00:49:45.671 | Sysmon | 11 | Temporary SOC003 marker file created |
| 00:49:45.675 | Sysmon | 12 | Temporary lab Registry key removed |
| 00:49:45.677 | PowerShell Operational | 4103 | Cleanup activity for the temporary marker file observed |

## Analyst assessment

The telemetry demonstrates cross-source correlation of one controlled activity sequence.

Security Event ID 4688 and Sysmon Event ID 1 independently recorded process creation. PowerShell Event IDs 4103/4104 provided command and script-block context, including visibility into the harmless payload associated with `-EncodedCommand`. Sysmon Event IDs 12/13 recorded Registry activity, while Event ID 11 recorded creation of the temporary marker file.

The Registry value was explicitly a benign lab marker and was not configured as persistence. The temporary Registry key and marker file were removed as part of the activity cleanup.

No Microsoft Defender 1116/1117 detection was observed. This is consistent with the benign exercise and is not interpreted as evidence of malware detection.

## What this evidence supports

This artifact supports practical experience with:

- Windows Security event analysis
- Sysmon endpoint telemetry
- PowerShell Operational logging
- process-creation correlation
- PowerShell encoded-command investigation
- Registry-event analysis
- file-creation telemetry
- multi-source timeline reconstruction
- evidence normalization and provenance handling

## Limitations

- This was an authorized lab exercise, not a production SOC incident.
- The exports are filtered EventRecord XML rather than full EVTX acquisition.
- The final collection window contained substantial background endpoint telemetry; attribution above is based on explicit SOC003 markers and temporal correlation.
- Absence of an Event ID in the collection window is not proof that the underlying capability or behavior cannot occur.
- Raw evidence is intentionally not published because it contains endpoint-specific identifiers.
