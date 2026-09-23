# Real Windows telemetry — PENDING retained evidence

SOC-2026-004 is synthetic. It does not close the real Windows event-log gap.

The preserved local branch `feature/soc-2026-003-windows-endpoint` contains the existing SOC-2026-003 plan, harmless activity script, UTC-window collector, evidence contract, ingestion and tests. At audit time it is not a remote branch. Do not push it or rerun activity merely to satisfy portfolio navigation. This document does not alter that implementation or its scope.

Use that branch's `07-lab/SOC-2026-003/README.md` and `collection/evidence-contract.md` for exact collection commands and acceptance criteria. A user-reported run is not a retained package inspected here. Recollect the original activity interval as documented; do not invent results.

Required review: private raw event XML plus manifest/metadata and hashes; channel/provider/event ID; original and normalized UTC time; record ID; pseudonymized host/account; collection errors and observed/unobserved IDs; unchanged source hashes; derived timeline and analyst rationale. Authentication and process events must be attributed to their actual provider. Absence of optional Defender events is not absence of threat.

Workflow after collection: verify package → ingest → inspect event content → distinguish FACT/INFERENCE/UNKNOWN → correlate bounded host/account/process context → investigate benign explanations → assign retrospective lab severity → hand off unresolved questions. Service/task persistence and account-change coverage are future scoped extensions, not claims about current collection.

Do not mark complete before retained real event content, completeness limitations and the analyst's interpretation have been reviewed. Native Windows PowerShell execution was not performed by this remediation.
