# SOC-2026-005 — findings

**Evidence basis: REAL CONTROLLED LAB.**

These findings are derived from the retained formal packet capture and its reviewed
TShark/Zeek derivatives. They describe an authorized local loopback laboratory
sequence, not a production incident.

## Findings matrix

| Evidence | Interpretation | Conclusion | Confidence |
|---|---|---|---|
| Formal PCAP: 84 packets; only `127.0.0.1` observed as an IP endpoint | Traffic is confined to the declared loopback laboratory boundary | No external network destination is present in the retained capture | High |
| One GET `/health.txt` with `Mozilla/5.0 SOC005-Benign-Control` | Explicit benign control provides comparison context | Control request is distinct from the repeated lab-agent sequence | High |
| Four GET requests with `SOC005-Lab-Agent/1.0`, `seq=1` through `seq=4`, approximately 1.03 s apart | Stable user agent, incrementing sequence parameter and regular timing form a beacon-like pattern worth investigating | Periodicity is observed; malicious beaconing is not established | High observation; low malicious interpretation |
| GET `/lab-update.bin` using the same lab-agent user agent after the repeated sequence | File retrieval is temporally associated with the repeated request sequence | File transfer occurred; causality and malicious payload delivery are not established | High observation |
| Server-side and downloaded artifact SHA-256 both `1bec000c532136b0d0558e834ef793f78e983f661c07c15fa2508fbeba71084e` | Served and downloaded bytes are identical | Byte identity of the controlled transfer is verified | High |
| Laboratory artifact content explicitly states that it is an authorized benign laboratory artifact | File content is inconsistent with a claim of retained malware evidence | No malware artifact is demonstrated by this case | High |
| TShark and Zeek agree exactly on method, host, URI and user agent for all six HTTP requests | Principal HTTP observations do not depend on one parser | Cross-parser agreement supports the retained request sequence | High |
| Default Zeek processing reports `bad_IP_checksum`; `zeek -C` produces connection/HTTP/file logs | macOS `NULL/Loopback` checksum behavior affects default Zeek parsing | `-C` is a disclosed analysis condition, not a repair or alteration of the PCAP | High |
| No HTTP Authorization, Proxy-Authorization, Cookie or Set-Cookie values; Zeek username/password values are `-` | No retained HTTP authentication/session material is present | No credential/session exposure is demonstrated in the public evidence set | High |

## Negative and control evidence

The retained evidence includes several observations that materially weaken a
malicious interpretation:

- every IP packet is loopback traffic;
- the scenario uses explicit `SOC005` and `SYN-LAB-005` laboratory markers;
- an explicit benign health request is present;
- the transferred file is intentionally benign;
- the source and downloaded file hashes are identical;
- no external destination is present;
- no credentials or HTTP session values are present;
- the sequence matches the predeclared authorized laboratory contract.

These facts do not make periodic HTTP traffic generally benign. They establish the
specific provenance and scope of this evidence set.

## Hypothesis assessment

### H1 — malicious beaconing followed by payload retrieval

**Assessment: not supported as the final explanation.**

Observations compatible with an initial H1 hypothesis include:

- approximately periodic HTTP requests;
- stable custom user agent;
- host-like query parameter;
- subsequent file retrieval.

However, the retained evidence does not establish:

- an external command-and-control destination;
- malicious process provenance;
- unauthorized execution;
- remote operator control;
- malicious file content;
- compromise;
- data exfiltration.

H1 is therefore not the best-supported explanation for this specific evidence set.

### H2 — authorized controlled-lab automation

**Assessment: strongly supported.**

Supporting evidence includes:

- loopback-only communication;
- explicit laboratory identifiers;
- prior scenario authorization;
- deterministic sequence numbering;
- formal capture timing consistent with the scenario;
- explicitly benign transferred content;
- matching server/download hashes.

H2 is the explanation most directly supported by retained evidence and documented
provenance.

### H3 — legitimate application health/update behavior

**Assessment: analytically plausible in an unknown environment, but not required
to explain this controlled case.**

Periodic network requests and subsequent file retrieval can also occur in
legitimate software. This remains an important alternative during real-world
triage, where laboratory provenance would not normally be available.

## Severity reassessment

### Initial laboratory triage priority

**Medium**

Rationale:

Repeated approximately periodic requests followed by a file retrieval using a
stable custom user agent justify investigation before authorization and provenance
are known.

### Correlated laboratory priority

**Informational / expected authorized activity**

Rationale:

Correlation established that the sequence is loopback-only, authorized, explicitly
laboratory-marked and associated with a benign controlled artifact.

This reassessment applies only to this laboratory evidence set. It is not a
production incident severity model.

## ATT&CK boundary

No MITRE ATT&CK technique is asserted as demonstrated attack behavior.

HTTP communication, periodicity and file retrieval are observable mechanics, but
the retained evidence does not establish the adversarial context required to claim
command-and-control, ingress tool transfer or another attack technique.

## Final analytical disposition

**Expected authorized controlled-lab activity — no malicious-incident escalation.**

The retained evidence supports H2 more strongly than H1 or H3 for this case.

No containment, credential reset, blocking or malware-remediation action is
warranted by the retained evidence.

If the same network pattern were observed without known laboratory provenance,
recommended enrichment would include:

- process and parent-process attribution;
- endpoint execution telemetry;
- destination ownership/reputation;
- DNS/TLS context where applicable;
- artifact provenance and analysis;
- authorization/change records;
- broader host and network scope.

## Confidence

- packet/request observations: **High**;
- approximately periodic timing: **High**;
- file-transfer byte identity: **High**;
- controlled-lab provenance: **High**;
- malicious intent: **Low / unsupported**;
- production-world generalization: **Not established**.

## Case-completion gate satisfied

The analytical disposition is complete and the case-level completion gate was
satisfied for validated pre-promotion candidate commit `00796a703cf77ab014d65481f8b23a21ac753a6b`:

1. the investigation record is reconciled with these findings;
2. final limitations were reviewed;
3. the complete candidate change set was validated;
4. push-triggered repository validation passed;
5. pull-request repository validation passed.

The case-level documentation is therefore promoted to a completed
**REAL CONTROLLED LAB** investigation. This status-only documentation promotion is
revalidated before merge.
