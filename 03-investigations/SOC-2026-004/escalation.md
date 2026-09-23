# SOC-2026-004 — Tier 2 escalation package (synthetic)

**Decision:** High triage priority; suspicious correlated activity, compromise not
confirmed. This is a drafted laboratory handoff, not a submitted incident ticket.

## Handoff

- Host: SYN-WIN-04; account SYNTH\ops.admin; session 0x900.
- Window: 2026-09-23 09:00:00–09:02:30 UTC.
- Trigger: SYS-005 Office-parent encoded PowerShell.
- Corroboration: SEC-009/010 unusual remote privileged session, SYS-006 network,
  SYS-007 Run value. [Timeline](timeline.csv), [findings](findings.md),
  [source dataset](../../02-datasets/soc-2026-004/README.md).
- Unknown impact: no acquired executable, confirmed malicious script, data loss or
  additional affected hosts. No containment performed.

## Tier 2 requests, in order of investigative value

1. Validate owner/change authorization and administrative source using independent
   records, not a potentially compromised endpoint's assertions.
2. Preserve volatile processes, sessions, connections and memory when authorized
   and proportionate. Record collection times, operator, tools and host time.
3. Export Security, Sysmon and PowerShell channels with original metadata; hash
   exports and retain originals. Acquire relevant user registry hive and transaction
   logs, executable if present, Office document and file metadata under approved
   handling. A fixture hash is integrity evidence, not chain of custody from a host.
4. Correlate session/GUID with EDR, authentication, proxy/DNS and script-block data.
   Assess whether Run entry executed and whether other hosts share the behavior.
5. Reassess severity and hypotheses as evidence arrives; document contradictions.

## Conditional response recommendations

If active unauthorized access is corroborated, coordinate endpoint network isolation
and session/account controls with the incident lead and owner. Preserve volatile
state first when operationally safe; imminent harm can justify containment before
collection. Record the trade-off. Avoid shutdown or deleting the Run value/file
before preserving relevant evidence. Credential resets and artifact removal require
confirmed scope, approved response and recovery planning; they are not automatic
outputs of these detections.

After remediation, validate absence of unauthorized autostart entries, review fresh
logons and process telemetry, and monitor recurrence before closure. Confirm restored
business function and record residual evidence gaps.

[DFIR collection checklist](../../03-dfir/compromised-host-collection-checklist.md)
and [artifact matrix](../../03-dfir/key-artifacts-matrix.md) support planning.
