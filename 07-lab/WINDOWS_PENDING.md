# SOC-2026-003 — PLANNED real Windows endpoint telemetry

SOC-2026-004 is synthetic and does not close this evidence gap. The public portfolio must not imply that SOC-2026-003 has a remotely available implementation or completed collection.

At the 2026-09-23 remote audit, the repository exposed only `main`, no tags and no Actions artifacts. The previously cited commit `ec12e5d713229fa7fb9afd027153d6604789b319` was not available through the GitHub commit API. Local development is not public evidence and is outside this publication branch; no local SOC-2026-003 implementation is modified or pushed by this change.

## Acceptance gate

Before changing the case from PLANNED, retain and privately review an authorized package containing raw event XML, collection manifest/metadata, hashes, channel/provider/event IDs, original and normalized UTC timestamps, record IDs, pseudonymized host/account context, collection errors and observed/unobserved IDs. Preserve original bytes and distinguish collection completeness from absence of suspicious behavior.

Then validate ingestion, derive a timeline, correlate the available host/account/logon/process identifiers, investigate benign explanations, document FACT/INFERENCE/UNKNOWN, assign justified lab severity and prepare an escalation with unresolved questions. Missing optional events do not prove absence of threat.

Do not invent collection results or rerun activity merely to populate a portfolio. A user-reported run does not replace inspected retained evidence. Native Windows execution and real event collection are not validated by the synthetic test suite.
