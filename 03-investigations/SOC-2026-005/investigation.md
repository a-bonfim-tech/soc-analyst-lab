# SOC-2026-005 — controlled network traffic investigation

**Status: COMPLETED — REAL CONTROLLED LAB.**

The retained packet capture and directly derived network telemetry are
**REAL CONTROLLED LAB** evidence. The analytical disposition is documented in
[findings](findings.md). The case-level completion gate was satisfied for the
validated pre-promotion candidate commit `00796a703cf77ab014d65481f8b23a21ac753a6b`: the investigation and
findings were reconciled, final limitations were reviewed, the complete candidate
change set was validated, and both push and pull-request repository checks passed.

This investigation concerns an authorized local loopback laboratory sequence. It
does not represent production SOC activity, customer traffic, malware execution or
real command-and-control.

## Scope and authorization

The formal sequence was generated on a macOS host using local loopback traffic only.

| Field | Value |
|---|---|
| Case | SOC-2026-005 |
| Capture interface | `lo0` |
| Client IP | `127.0.0.1` |
| Server IP | `127.0.0.1` |
| Server port | `18080/TCP` |
| Protocol | HTTP over TCP |
| Capture filter | `tcp port 18080` |
| Formal capture start | 2026-09-24 18:16:05 UTC |
| Formal sequence end | 2026-09-24 18:16:11 UTC |
| Formal capture end | 2026-09-24 18:16:13 UTC |
| PCAP packets | 84 |
| PCAP SHA-256 | `5f3c3450a87710db595bfc8892b177c28afef9ef86349dc5b30b72caea908643` |

Primary retained evidence:
[`../../10-evidence/SOC-2026-005/network-traffic/`](../../10-evidence/SOC-2026-005/network-traffic/).

Scenario contract:
[`../../07-lab/SOC-2026-005/SCENARIO_CONTRACT.md`](../../07-lab/SOC-2026-005/SCENARIO_CONTRACT.md).

## Alert and source evidence

There was no production SIEM, IDS or EDR alert.

The investigative trigger is an analyst-defined laboratory review of a retained
packet capture containing a repeated HTTP request pattern followed by file
retrieval.

TShark and Zeek independently identify six HTTP GET requests in the formal PCAP.

The retained PCAP contains only `127.0.0.1` as an IP endpoint.

## OBSERVATION / reference

### O1 — benign control request

At `2026-09-24 18:16:07.570357 UTC`, the capture contains:

- method: `GET`;
- host: `127.0.0.1:18080`;
- URI: `/health.txt`;
- user agent: `Mozilla/5.0 SOC005-Benign-Control`;
- HTTP response: `200`.

Evidence:

- `10-evidence/SOC-2026-005/network-traffic/derived/tshark-http.txt`
- `10-evidence/SOC-2026-005/network-traffic/derived/zeek/http.log`

### O2 — four repeated lab-agent requests

Four requests use the same user agent:

`SOC005-Lab-Agent/1.0`

Observed URIs:

1. `/beacon.txt?host=SYN-LAB-005&seq=1`
2. `/beacon.txt?host=SYN-LAB-005&seq=2`
3. `/beacon.txt?host=SYN-LAB-005&seq=3`
4. `/beacon.txt?host=SYN-LAB-005&seq=4`

Their observed request timestamps are:

- `18:16:07.588569 UTC`;
- `18:16:08.626359 UTC`;
- `18:16:09.656018 UTC`;
- `18:16:10.685677 UTC`.

Inter-request intervals are approximately:

- `1.037790 s`;
- `1.029659 s`;
- `1.029659 s`.

Mean interval: approximately `1.032369 s`.

This establishes a repeated approximately periodic request pattern. It does not
establish malicious beaconing.

### O3 — subsequent file retrieval

At `2026-09-24 18:16:11.727511 UTC`, the same
`SOC005-Lab-Agent/1.0` user agent requested:

`/lab-update.bin`

The HTTP response status was `200`.

The server-side laboratory artifact and downloaded copy both had SHA-256:

`1bec000c532136b0d0558e834ef793f78e983f661c07c15fa2508fbeba71084e`

The retained validation therefore establishes byte identity between the served and
downloaded laboratory artifact.

It does not establish malware delivery.

### O4 — parser agreement

TShark and Zeek agree exactly on all six requests for:

- method;
- HTTP host;
- URI;
- user agent.

This reduces dependence on one parser for the principal HTTP observations.

### O5 — publication and traffic boundary

Publication review found:

- only `127.0.0.1` as an IP endpoint;
- no HTTP Authorization value;
- no Proxy-Authorization value;
- no Cookie value;
- no Set-Cookie value;
- no actual Zeek username value;
- no actual Zeek password value.

The words `username` and `password` present in the Zeek HTTP log are schema field
names. All six corresponding values are `-`.

### O6 — Zeek checksum behavior

Default Zeek processing of the macOS `NULL/Loopback` PCAP recorded:

`bad_IP_checksum`

and did not produce normal connection/HTTP logs.

The same retained PCAP was analyzed with:

`zeek -C`

which disables checksum validation during offline analysis. That run produced
`conn.log`, `http.log` and `files.log`.

The `-C` option does not modify or repair the captured PCAP.

TShark independently parsed the HTTP sequence from the original retained PCAP.

## INFERENCE / rationale / alternatives

### I1 — periodicity warrants investigation

The approximately one-second spacing, stable custom user agent and incrementing
sequence parameter form a recognizable repeated request pattern.

That pattern is sufficient to justify analyst review but is not sufficient to infer
command-and-control.

### I2 — temporal association with file retrieval

The file request occurs after the four repeated requests and uses the same custom
user agent.

This supports temporal and client-identifier association within the controlled
sequence.

Temporal association alone does not establish that the repeated requests caused
the file transfer.

### I3 — malicious interpretation is not supported by network evidence alone

The network evidence does not establish:

- malware execution;
- compromise;
- command execution;
- remote operator control;
- data exfiltration;
- persistence;
- credential theft;
- an external malicious destination.

The retained loopback context and laboratory provenance materially constrain the
interpretation.

## HYPOTHESIS / falsification test

### H1 — malicious beaconing followed by payload retrieval

Evidence superficially consistent with H1:

- repeated approximately periodic HTTP requests;
- stable custom user agent;
- host-like query parameter;
- later file retrieval using the same user agent.

Evidence missing for H1:

- malicious destination attribution;
- malware/process provenance;
- endpoint execution evidence;
- command-and-control content;
- malicious file classification;
- unauthorized activity.

Current assessment: **not supported as the final explanation** by retained
evidence.

### H2 — authorized controlled-lab automation

Evidence consistent with H2:

- all network communication is loopback-only;
- scenario identifiers use explicit `SOC005` / `SYN-LAB-005` markers;
- the request sequence matches the predeclared scenario contract;
- the transferred artifact is explicitly benign;
- source and downloaded artifact hashes match;
- capture occurred inside the declared formal time boundary.

Current assessment: **strongly supported by retained evidence and scenario
provenance**.

### H3 — legitimate application health/update behavior

The observable network pattern could also resemble benign application telemetry or
update activity if viewed without laboratory provenance.

This remains a valid general alternative when evaluating periodic HTTP traffic, but
the explicit scenario markers and controlled-lab provenance make H2 more directly
supported for this specific evidence set.

## UNKNOWN / NOT VERIFIED

The following are not demonstrated by this evidence set:

- process ID responsible for each client connection;
- process tree or parent process;
- authenticated user responsible for traffic generation;
- DNS activity;
- TLS metadata;
- external destination reputation;
- production asset criticality;
- production authorization/change-ticket state;
- EDR/SIEM alert behavior;
- IDS/IPS detection efficacy;
- whether a comparable real-world pattern would be malicious.

These gaps must not be silently filled from the known laboratory script.

## Timeline and correlations

See [`timeline.csv`](timeline.csv).

Minimum defensible sequence:

| UTC | Observation |
|---|---|
| 18:16:07.570357 | benign control GET `/health.txt` |
| 18:16:07.588569 | repeated-request sequence 1 |
| 18:16:08.626359 | repeated-request sequence 2 |
| 18:16:09.656018 | repeated-request sequence 3 |
| 18:16:10.685677 | repeated-request sequence 4 |
| 18:16:11.727511 | GET `/lab-update.bin` |

The four repeated requests have approximately one-second spacing. The file request
follows them by approximately one second.

## Severity before/after and rationale

### Initial laboratory triage priority: Medium

Before provenance is correlated, repeated approximately periodic requests followed
by file retrieval using the same custom user agent justify review.

This is a laboratory triage priority, not a production incident severity.

### Correlated laboratory priority: Informational / expected authorized activity

After correlation with:

- loopback-only endpoints;
- formal scenario contract;
- explicit laboratory markers;
- benign artifact content;
- matching source/download hashes;
- known authorization;

the retained evidence supports expected controlled-lab automation rather than an
unauthorized incident.

No production severity is assigned.

## Candidate ATT&CK mapping with evidence

No ATT&CK technique is asserted as demonstrated attack behavior for this case.

HTTP is directly observed, but protocol use alone does not establish malicious
Application Layer Protocol behavior. File retrieval is directly observed, but the
artifact is benign and the evidence does not establish transfer into a compromised
environment.

This case therefore does not convert generic network mechanics into ATT&CK coverage
without the behavioral context required for such a claim.

## Decision / RECOMMENDATION / authority

Current analyst decision:

**Do not escalate as a malicious incident based on the retained case evidence.**

The most strongly supported explanation is authorized controlled-lab automation.

In an unknown real-world environment, comparable periodic HTTP traffic followed by
file retrieval should be enriched with endpoint/process provenance, destination
context, authorization state and artifact analysis before closure or escalation.

## Actions actually performed

Performed:

- captured formal loopback PCAP;
- calculated and retained PCAP SHA-256;
- parsed HTTP traffic with TShark;
- parsed the same PCAP with Zeek using disclosed `-C` checksum handling;
- retained default Zeek checksum diagnostic;
- compared TShark and Zeek request observations;
- verified source/download artifact byte identity;
- reviewed the PCAP for publication boundary;
- verified absence of HTTP authorization/cookie values;
- retained selected public evidence.

Not performed:

- endpoint containment;
- credential reset;
- process termination;
- firewall blocking;
- production escalation;
- malware remediation.

## Limitations and analyst summary

This case demonstrates packet capture review, HTTP request correlation, timing
analysis, cross-parser validation, file-transfer verification, publication review
and evidence-bound reasoning in a controlled laboratory.

The primary limitation is that the traffic is deliberately generated loopback HTTP
traffic. It therefore cannot demonstrate real-world network attribution,
production detection efficacy or malicious behavior.

The Zeek checksum limitation is explicitly retained rather than hidden: default
processing reports `bad_IP_checksum` for the macOS loopback capture, while `-C`
allows offline analysis and TShark independently confirms the principal HTTP
observations.

Final analytical disposition is documented in [findings](findings.md).
Case-level completion criteria were satisfied for validated pre-promotion candidate
commit `00796a703cf77ab014d65481f8b23a21ac753a6b`. This status-only documentation promotion is revalidated before
merge.
