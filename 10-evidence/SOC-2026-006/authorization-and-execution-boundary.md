# SOC-2026-006 — Authorization and Execution Boundary

## Authorization

SOC-2026-006 was conducted as an authorized controlled laboratory exercise on a disposable Windows endpoint.

The planned signal-generation method was the Microsoft-documented Defender for Endpoint EDR detection test.

The test method was selected to verify genuine Defender for Endpoint sensor, service and alert behavior without introducing real malware.

No production endpoint, customer environment or unauthorized system was within scope.

## Retained execution evidence

The retained evidence establishes that:

- the disposable laboratory endpoint was reporting Microsoft Defender for Endpoint telemetry;
- genuine Defender for Endpoint PowerShell-related alerts were generated;
- Microsoft Defender XDR associated the detections with an incident;
- endpoint process telemetry was available for investigation;
- Defender Advanced Hunting was used during the investigation;
- Microsoft Sentinel separately received relevant Microsoft security telemetry;
- analyst triage, severity assessment, disposition and incident resolution were recorded.

## Test method

The scenario contract specified use of the Microsoft-documented Defender for Endpoint EDR detection test.

The exact test command is intentionally not reproduced in this public artifact.

The observed Defender detections were reconciled during the investigation with the authorized laboratory detection-test scenario.

## Formal execution-window limitation

A separate contemporaneous record containing the exact start and end time of the authorized EDR test execution was not retained.

The first retained Defender alert timestamp must not be substituted for the test execution timestamp.

Filesystem creation or modification timestamps of later evidence exports must not be interpreted as the test execution time.

Consequently, the exact formal test-window correlation required by the scenario contract cannot be independently demonstrated retrospectively.

This is an explicit evidence gap.

## Closure impact

The retained evidence supports that the investigated activity occurred within the authorized controlled laboratory scenario and that no reviewed evidence established an unauthorized compromise.

However, because an independently retained formal execution window is unavailable, the repository does not claim that the scenario contract's formal test-window correlation gate was fully satisfied.

The actual Microsoft Defender XDR disposition and the analyst assessment remain documented separately and are not rewritten to compensate for this evidence gap.

## Evidence discipline

This limitation is preserved deliberately rather than backfilling a fictional execution time.

Future controlled investigations should create the authorization record and formal execution window before executing the test and retain those records as part of the evidence package.
