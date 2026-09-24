# SOC-2026-003 — real-telemetry evidence contract

Authority: [existing lab plan](../lab-plan.md). This contract governed collection
from the authorized disposable Windows 11 ARM64 VM used for SOC-2026-003.

The completed exercise produced real endpoint-generated Windows telemetry. Endpoint-
specific hostname, account and raw evidence details remain private; the public
repository contains sanitized derived evidence and analyst documentation.

**REAL TELEMETRY:** events actually produced by the Windows endpoint during the
authorized lab.

**NOT REAL TELEMETRY:** hand-written JSON/CSV fixtures, reconstructed events, copied
TryHackMe data, generated mock logs, or manually invented event records. Never
substitute these when actual telemetry is absent. SOC-2026-004 is not evidence for
this case. Temporary unit-test XML is software-test input only.

## Sources and fields

| Source | Requirement | Selected event families |
|---|---|---|
| Security | Required for case collection readiness | 4624/4625 authentication, 4672 assigned privileges, 4688 process creation |
| Microsoft-Windows-Sysmon/Operational | Required for case collection readiness | 1 process, 3 network, 11 file creation, 12/13/14 registry |
| Microsoft-Windows-PowerShell/Operational | Optional, record gaps | 4103 module and 4104 script-block events |
| Microsoft-Windows-Windows Defender/Operational | Optional, record gaps | 1116 detection, 1117 action; benign activity need not produce these |

Source availability does not establish auditing/filter coverage. Operator must verify
expected audit categories, process-command-line policy, Sysmon configuration and
PowerShell settings before the exercise. Do not turn controls on through this
package. Configure a separate approved VM image if prerequisites are missing.
No-event results are not invented into events or evidence of absent activity.
No requirement to induce Defender detections. The collector lists observed and
unobserved selected event IDs, including for required channels. The importer reports
coverage from validated events separately; it does not parse partial exports. An
unobserved ID is a limitation, not proof that its audit policy/filter is disabled.

Every accepted source event must have native System fields: Provider Name, EventID,
EventRecordID, TimeCreated SystemTime with timezone, Computer and Channel. Retain
all original XML including event-specific payloads. Review relevant payload fields
when present: user/SID, LogonId, LogonType, IP/port, image/parent image, command line,
ProcessGuid, registry object/details and hashes. Missing fields remain missing;
not every event type supplies every field. Source EventData is not rebuilt to fit a
synthetic schema. XML exports preserve EventRecord.ToXml values, not original EVTX
container bytes or every event in a channel.

## Time, identity and provenance

- Collect baseline and final packages separately, using explicit UTC bounds (maximum
  two hours each). Record requested window and actual export start/end, timezone,
  actual hostname, collector identity, OS, PowerShell version and script SHA-256.
- The query interval is inclusive: start <= native SystemTime <= end. Explicit UTC
  XPath bounds retain seven fractional digits and bypass FilterHashtable's local-time
  reinterpretation. Metadata retains requested UTC bounds unchanged. No timezone
  constant, window widening or local wall-clock assumption is used.
- Event timestamps remain verbatim in raw XML. Derived UTC timestamps retain seven
  fractional digits; original timestamp strings remain available separately.
- Preserve native hostnames privately, including source FQDN if present. Importer
  compares the short hostname with collector hostname. One package represents one
  endpoint. Record VM snapshot/clock sync state in private operator notes; do not
  invent missing clock accuracy or provenance metadata.
- Hash source files and metadata with SHA-256. Manifest covers those bytes; a separate
  checksum covers manifest.json. Verify after transfer. Checksums detect changes,
  not authenticity: independent operator attestation and collection notes remain
  required. Keep source originals read-only in approved private evidence storage.
- Source XML/metadata are source exports; events.jsonl and ingestion.json are derived
  analyst artifacts. Keep them outside source directories and outside public Git.

## Privacy boundary

Use a fresh disposable VM with lab-only accounts and no real documents, credentials,
cloud sign-in, browser sessions, tokens or personal activity. The collector reads
only the listed channels/IDs/time window; it does not read credential stores, keys,
browser databases, LSASS or memory. Event payloads themselves can contain sensitive
command lines, account identifiers or script text. No automated privacy guarantee
is possible. If the VM is not clean, do not run this package there.

Keep raw packages private. Before any publication manually inspect a separate copy,
remove confidential payloads, pseudonymize identifying values consistently and record
redaction method and original/derived hashes privately. Never edit the raw package
in place or present redacted bytes as original exports. No public case evidence is
created in this pass. Exclude TryHackMe questions, answers, flags, credentials, target
identifiers and proprietary room data entirely.

## Analytical and provenance model — apply only after collection

For each eventual finding record: source filename/hash + channel/record ID;
**Evidence** (direct observation); **Interpretation** (possible meaning and alternatives);
**Conclusion** (corroborated support only); **Confidence** (high/medium/low with basis).

Before stating provenance, verify that the authorized operator collected events from
the Windows endpoint and derived artifacts came only from those source records.
Record authorization, activity notes and transfer verification. Do not claim these
steps happened before the operator performs them. No compromise, account abuse,
malicious execution or successful persistence is concluded at preparation time.
