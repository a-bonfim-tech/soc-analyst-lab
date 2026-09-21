# SOC-2026-001 — Controlled Lab Evidence

This directory contains telemetry generated during a controlled reproduction of
behaviors documented in SOC-2026-001.

Environment:

- Target hostname: srv-web-01
- Target IP: 10.10.20.10
- Attacker-simulation hostname: kali-redteam-01
- Source IP: 10.10.20.45
- Container image: Ubuntu 24.04
- Telemetry sources: OpenSSH and sudo
- Execution environment: isolated Docker network

Evidence:

- `real-lab-auth.txt`

Observed laboratory behavior includes:

- failed SSH password authentication;
- successful SSH password authentication;
- privileged access to `/etc/shadow`.

The contents of `/etc/shadow` were not captured.

This is real telemetry from a controlled laboratory reproduction. It is not
original incident evidence.

SHA-256:

`100edcdc35f1a4f36e8158e128cac3d1b86d3c05186aadc74107017fe217e665`
