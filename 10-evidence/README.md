# Evidence

Evidence suitable for version control after sanitization or explicit publication
review.

## SOC-2026-005 — network traffic evidence

The [SOC-2026-005 network evidence package](SOC-2026-005/network-traffic/README.md)
contains a publication-reviewed controlled-lab PCAP, TShark HTTP extraction,
Zeek connection/HTTP/file telemetry, checksum-diagnostic evidence, capture
metadata, tool versions and SHA256 integrity records.

The package is **REAL CONTROLLED LAB** evidence. It does not represent production
SOC traffic, customer traffic, malware execution or real command-and-control.

Sensitive or unreviewed raw evidence must remain outside the Git repository.
Raw artifacts may be retained only when the case documentation establishes an
appropriate controlled evidence boundary and publication review.
