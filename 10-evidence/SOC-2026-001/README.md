# SOC-2026-001 — Controlled Lab Evidence

This directory contains telemetry generated during a controlled reproduction of
behaviors documented in SOC-2026-001.

Environment:

- Target identity: intentionally omitted from the public retained excerpt
- Source identity: intentionally omitted from the public retained excerpt
- Published source IP: 192.0.2.45 (TEST-NET-1 documentation address)
- Container image: Ubuntu 24.04
- Telemetry sources: OpenSSH and sudo
- Execution environment: isolated Docker network

Evidence:

- `real-lab-auth.txt`

Observed laboratory behavior includes:

- failed SSH password authentication;
- successful SSH password authentication;
- a privileged command record referencing `/etc/shadow`.

The contents of `/etc/shadow` were not captured.

This is real telemetry from a controlled laboratory reproduction. It is not
original incident evidence. The public copy is sanitized: internal addressing
and the laboratory account name were replaced while preserving the observable
event sequence and analyst-relevant behavior.

SHA-256:

`3ff9508275a3d8f21f62ca9dd7e5f763c5a8d56a5be67edf086a575bc3aaf903`
