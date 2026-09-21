# SOC-2026-002 — Cloud Authentication Investigation

## Purpose

Investigate a simulated cloud identity authentication sequence using KQL and a synthetic SigninLogs-style dataset in Azure Data Explorer.

This exercise is designed to reproduce a Tier 1 SOC workflow applicable to Microsoft Sentinel-style authentication investigations.

## 1. Data Source

- Platform: Azure Data Explorer Free Cluster
- Database: SOC2026002
- Table: SigninLogs
- Dataset: Synthetic
- Events ingested: 22
- Query language: KQL

The dataset is synthetic and must not be represented as production Microsoft Entra ID or Microsoft Sentinel telemetry.

## 2. Initial Observation

Eight authentication failures were identified in the dataset.

Six consecutive failures were associated with:

- User: alex.meyer@contoso-lab.example
- Source IP: 203.0.113.77
- Location: NL
- Application: Azure Portal
- Result: 50126 — Invalid username or password
- Window: 20:31:02–20:32:33 UTC

Two additional authentication failures belonged to other users and did not exhibit the same repeated-failure pattern.

## 3. Timeline

- 20:31:02 — Authentication failure from 203.0.113.77.
- 20:31:19 — Authentication failure.
- 20:31:37 — Authentication failure.
- 20:31:55 — Authentication failure.
- 20:32:14 — Authentication failure.
- 20:32:33 — Authentication failure.
- 20:33:01 — Successful authentication to Azure Portal.
- 20:34:12 — Successful authentication to Microsoft 365.
- 20:36:40 — Successful authentication to SharePoint Online.

## 4. User Baseline Comparison

Observed source history for alex.meyer@contoso-lab.example:

### 192.0.2.21 / DE

- Events: 3
- Successful authentications: 3
- Failed authentications: 0

### 203.0.113.77 / NL

- Events: 9
- Successful authentications: 3
- Failed authentications: 6

Within the available synthetic dataset, 203.0.113.77 represents a new source and location for the account.

The available history is limited and therefore cannot establish a production-quality behavioral baseline.

## 5. Risk Context

All nine events from 203.0.113.77 are marked:

- IsRisky: true
- RiskEventTypes_V2: unfamiliarFeatures

These values are synthetic scenario attributes and do not represent an actual Microsoft Entra ID Protection assessment.

## 6. Detection Logic

The KQL detection identifies a user and source IP where:

1. five or more authentication failures occur;
2. a successful authentication subsequently occurs;
3. the success occurs within five minutes after the last failure.

Detection artifact:

`04-detection-rules/kql/SOC-2026-002/repeated-failures-followed-by-success.kql`

The query returned one result:

- UserPrincipalName: alex.meyer@contoso-lab.example
- IPAddress: 203.0.113.77
- FailureCount: 6
- FirstFailure: 20:31:02 UTC
- LastFailure: 20:32:33 UTC
- FirstSuccess: 20:33:01 UTC

## 7. Analytical Hypothesis

Primary hypothesis:

The sequence is consistent with repeated credential guessing followed by a successful authentication and subsequent access to multiple cloud applications.

Alternative explanations may include:

- user password-entry errors followed by successful authentication;
- automated authentication retries;
- legitimate travel or VPN use;
- controlled security testing.

The telemetry alone does not establish malicious intent or confirmed account compromise.

## 8. MITRE ATT&CK Candidates

- T1110.001 — Password Guessing
- T1078 — Valid Accounts (candidate after successful authentication)

ATT&CK mappings describe observed behavior and do not independently establish compromise.

## 9. Disposition

Suspicious authentication activity — requires contextual validation.

Compromise status: Not confirmed.

## 10. Severity Assessment

Recommended simulated Tier 1 severity: Medium.

Rationale:

Repeated authentication failures were followed by a successful sign-in from the same new source and subsequent access to additional cloud applications. Risk indicators are also present in the synthetic dataset.

Severity could increase if additional evidence established unauthorized access, sensitive-data activity, privilege changes, persistence, or confirmed credential compromise.

## 11. Tier 1 Recommendation

Escalate for:

- user verification;
- source-IP and location validation;
- authentication-method review;
- MFA and Conditional Access review;
- session and token investigation;
- review of post-authentication cloud activity;
- determination of whether credentials were compromised.

## 12. Limitations

- Dataset is synthetic.
- Azure Data Explorer was used instead of a production Microsoft Sentinel workspace.
- No real Microsoft Entra ID tenant telemetry was analyzed.
- No device, MFA, Conditional Access, token, endpoint, or network telemetry is available.
- Geographic information is scenario data, not independent IP geolocation.
- The historical baseline is intentionally small.

## 13. Current Conclusion

The KQL investigation successfully identified a repeated-failure-followed-by-success authentication pattern while excluding isolated benign-style failures included in the dataset.

The activity is classified as suspicious for training purposes, but account compromise is not confirmed.
