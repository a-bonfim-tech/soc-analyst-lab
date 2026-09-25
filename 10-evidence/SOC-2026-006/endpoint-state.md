# SOC-2026-006 — Endpoint State Evidence

## Environment

- Endpoint type: authorized disposable Windows laboratory endpoint
- Security platform: Microsoft Defender for Endpoint
- Investigation environment: controlled laboratory
- Production/customer endpoint: no

## Endpoint reporting

**Evidence state: SUPPORTED**

The retained evidence supports that the laboratory endpoint was reporting telemetry to Microsoft Defender for Endpoint.

Supporting evidence includes:

- genuine Microsoft Defender for Endpoint alerts generated from activity on the laboratory endpoint;
- Microsoft Defender XDR correlation of those alerts into an incident;
- Microsoft Defender Advanced Hunting `DeviceProcessEvents` telemetry for the endpoint;
- Microsoft Sentinel `DeviceProcessEvents` telemetry ingested through the Microsoft security integration;
- retained post-closure telemetry-validation results.

This establishes operational endpoint telemetry reporting during the scenario.

## Endpoint onboarding

**Evidence state: NOT INDEPENDENTLY RETAINED**

The runtime evidence is consistent with an endpoint that had been operationally onboarded to Microsoft Defender for Endpoint because Defender received endpoint telemetry and generated genuine endpoint detections.

However, no separate contemporaneous onboarding-state artifact was retained that independently records the Defender portal onboarding state or onboarding completion event.

Therefore the scenario-contract onboarding-evidence requirement is not retrospectively marked as independently satisfied by inference from later telemetry.

## Evidence distinction

Endpoint reporting and endpoint onboarding are treated as separate evidence requirements.

Observed telemetry can support the reporting state, but this document does not substitute later telemetry for a missing contemporaneous onboarding-state record.

No onboarding screenshot, portal-state export or equivalent artifact is fabricated or retrospectively reconstructed.

## Public/private boundary

Raw Defender and Microsoft Sentinel exports remain private.

Unnecessary tenant, subscription, workspace, device, user, alert and incident identifiers are excluded from this public evidence record.

## Contract impact

- Endpoint reporting evidence: supported by retained runtime telemetry.
- Endpoint onboarding evidence: operationally consistent with successful onboarding, but no independent contemporaneous onboarding-state artifact was retained.
- Formal EDR test execution window: remains a separate documented evidence gap.
- Exact candidate-commit repository validation: remains pending until the final candidate commit exists.
