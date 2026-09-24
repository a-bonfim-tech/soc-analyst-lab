# SOC-2026-005 — network traffic evidence

## Evidence classification

The packet capture and directly derived network telemetry in this directory are
**REAL CONTROLLED LAB** evidence.

They were generated from an authorized local loopback laboratory sequence. This
classification applies to the retained artifacts themselves. The SOC-2026-005 case
is **COMPLETED — REAL CONTROLLED LAB**. Investigation, timeline, findings,
analytical disposition, final limitations review and repository validation were
completed for validated pre-promotion candidate commit `00796a703cf77ab014d65481f8b23a21ac753a6b`. This
status-only documentation promotion is revalidated before merge.

This evidence does not represent production SOC traffic, customer traffic, malware
execution or real command-and-control activity.

## Formal capture

- interface: macOS `lo0`;
- capture filter: `tcp port 18080`;
- client: `127.0.0.1`;
- server: `127.0.0.1:18080`;
- protocol: HTTP over TCP;
- packet count: 84;
- HTTP request count: 6;
- PCAP SHA-256:
  `5f3c3450a87710db595bfc8892b177c28afef9ef86349dc5b30b72caea908643`.

The retained PCAP was reviewed before publication. The review observed only
loopback IP traffic and found no HTTP Authorization, Proxy-Authorization, Cookie or
Set-Cookie material.

## Observed request sequence

The capture contains:

1. one benign health request using `Mozilla/5.0 SOC005-Benign-Control`;
2. four approximately periodic requests using `SOC005-Lab-Agent/1.0`;
3. one subsequent request for `/lab-update.bin` using the same lab-agent user
   agent.

The repeated request pattern is described as beacon-like for analytical purposes.
That description does not establish malicious command-and-control behavior.

## Independent parsing

The retained HTTP sequence was parsed independently with TShark and Zeek.

Both parsers produced the same six request records for:

- HTTP method;
- host;
- URI;
- user agent.

## Zeek checksum limitation

Default Zeek processing of the macOS `NULL/Loopback` capture reported
`bad_IP_checksum` and did not produce normal connection and HTTP telemetry.

The retained Zeek analysis was therefore generated with checksum validation
disabled using `zeek -C`.

This does not modify or repair the PCAP. It changes Zeek's checksum-validation
behavior during offline analysis. TShark was used as an independent parser for the
HTTP observations.

The default Zeek diagnostic is retained separately under `diagnostics/`.

## Directory structure

- `raw/` — formal packet capture;
- `derived/tshark-http.txt` — TShark-derived HTTP request table;
- `derived/zeek/` — Zeek connection, HTTP and file-analysis logs generated with
  `-C`;
- `metadata/` — capture metadata, tool versions and source-artifact hashes;
- `diagnostics/` — retained checksum diagnostic from default Zeek processing.

## Evidence boundary

Hashes establish byte consistency of retained artifacts, not source authenticity
outside this controlled laboratory.

The HTTP file-transfer observation establishes that bytes were transferred. It does
not establish malware delivery. The laboratory file used in the scenario was
explicitly benign, and the served and downloaded copies had identical SHA-256
values during formal validation.

Analyst conclusions and final disposition belong in the investigation record, not
in this raw evidence directory.
