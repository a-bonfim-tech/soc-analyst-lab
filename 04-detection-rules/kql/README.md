# KQL evidence states and pending runtime gate

| State | Required evidence |
|---|---|
| KQL_SYNTAX_ONLY | Syntax review or parser check only; name the tool |
| KQL_WRITTEN | Query source and table contract retained |
| KQL_TESTED | Actual named KQL engine test with retained input, output and assertion |
| KQL_EXECUTED | Actual engine execution with retained output, timestamp, environment and exact query |
| KQL_RESULT_RETAINED | Reviewed result export linked to input and query hashes |

Current four queries: **KQL_WRITTEN**. SOC-2026-002 execution is reported historically but not verified by a retained output. SOC-2026-004 has no runtime execution. Python tests are restricted local models, not KQL syntax/backend validation.

| Query | Purpose / assumptions | Expected fields / interpretation | Benign alternatives / limits |
|---|---|---|---|
| [002 authentication](SOC-2026-002/repeated-failures-followed-by-success.kql) | Custom SigninLogs-style fixture; correlate same account/IP failures in preceding 5 minutes | UserPrincipalName, IPAddress, FailureCount, FirstFailure, LastFailure, SuccessTime, SuccessApp; expected one qualifying account/IP | Retries, password errors, travel/VPN; synthetic risk and short baseline; no compromise proof |
| [004 PowerShell](SOC-2026-004/suspicious-powershell.kql) | Custom Sysmon004 process table per query comments | Projected event, host, user, image, parent and command fields; investigate encoded Office-child process | Authorized automation; narrow strings miss variants; no malicious intent proof |
| [004 admin logon](SOC-2026-004/unusual-admin-logon.kql) | Security004 plus AssetContext004; explicit account/source enrichment | Projected authentication and source context; outside configured baseline | Planned administration, stale inventory, VPN; no adversarial use proof |
| [004 Run value](SOC-2026-004/registry-run-key-persistence.kql) | Sysmon004 registry table | Projected target/value and process context; suspicious configuration | Installers and updaters; Public path is not effective-ACL evidence; no persistence execution proof |

## PENDING execution procedure

1. Use an authorized isolated Kusto environment; record product/version, database/table schema, query text/hash and UTC interval. Do not claim Sentinel from an ADX run.
2. Import only the existing synthetic fixtures using the exact types and names in each query. Retain import diagnostics and input hash. No production tenant is required.
3. Execute source query unchanged; retain sanitized CSV/JSON output, row count, errors, duration and UTC time. Empty output is a result, not permission to invent rows.
4. Compare with the documented fixture expectations. Run existing benign controls plus boundary inputs and retain every output. Model agreement does not prove platform equivalence.
5. Add account and source-IP summaries using the same imported fields; retain exact queries and results. Extend process hunting only where telemetry supports it. Record failed/changed queries honestly.
6. Store private originals separately; publish only reviewed derivatives under case evidence. Record redactions and hashes. Remove only lab resources created by this exercise.

Acceptance: a reviewer can trace query → schema → input → engine → output → interpretation → limits. Until that package exists, leave runtime status NOT VERIFIED.
