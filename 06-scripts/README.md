# Scripts

Defensive automation, log parsing, enrichment, and SOC utility scripts.

## Sigma backend translation validator

`validate_sigma_backend_translation.py` reproduces the retained
SOC-2026-004 Sigma backend translation behavior in an isolated environment
defined by `requirements-sigma-backend.txt`.

The validator checks:

- the pinned pySigma and Kusto backend versions;
- source-rule SHA-256 values;
- deterministic PowerShell and Registry backend query output;
- emitted-query hashes and retained `.kql` file hashes;
- byte-for-byte equality between generated and retained backend queries;
- the expected `SigmaTransformationError` for the enriched admin rule and
  its `PrivilegedAccount` blocking field.

This validator performs backend translation only. It does not execute Azure
Data Explorer / Kusto, Microsoft Defender XDR or Microsoft Sentinel, and it
does not establish production detection efficacy.
