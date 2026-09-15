# SOC Alert Triage Runbook

## Purpose

Provide a repeatable procedure for Tier 1 SOC analysts to validate, investigate, classify, document, and escalate security alerts.

## 1. Alert Identification

- Alert ID:
- Timestamp:
- Detection source:
- Detection rule:
- Severity:
- Affected asset:
- Affected user:
- Source IP:
- Destination IP:

## 2. Initial Validation

Determine:

- What triggered the alert?
- Which telemetry generated it?
- Is the detection technically plausible?
- Is the timestamp consistent?
- Is the affected asset correctly identified?
- Is sufficient evidence available to begin triage?

Do not assume malicious activity solely because an alert fired.

## 3. Context Collection

Collect relevant context:

- Asset hostname
- Asset criticality
- Operating system
- User/account
- Source and destination IP addresses
- Source and destination ports
- Protocol
- Process
- Parent process
- Command line
- Authentication events
- Network activity
- Related alerts

## 4. Investigation

Document:

### Evidence

What evidence is directly observable?

### Timeline

Reconstruct relevant events chronologically.

### Indicators

Identify relevant:

- IP addresses
- Domains
- URLs
- File hashes
- Filenames
- Processes
- User accounts

### Hypotheses

State possible explanations for the observed behavior.

Separate:

- observed fact
- inference
- hypothesis

## 5. MITRE ATT&CK Mapping

- Tactic:
- Technique:
- Sub-technique:
- Technique ID:

Only map behavior supported by available evidence.

## 6. Disposition

Select one:

- True Positive
- False Positive
- Benign Positive
- Inconclusive

## 7. Severity Assessment

Assess:

- Asset criticality
- User/account privilege
- Scope
- Confidence
- Potential impact
- Evidence of compromise

Severity:

- Informational
- Low
- Medium
- High
- Critical

## 8. Decision

Select the appropriate action:

- Close
- Continue monitoring
- Request additional evidence
- Escalate to Tier 2
- Initiate containment according to authorized procedure

## 9. Analyst Justification

Document:

- Evidence supporting the disposition
- Evidence supporting severity
- Reason for closure or escalation
- Remaining uncertainties
- Additional evidence required

## 10. Escalation Package

When escalating, provide:

- Alert summary
- Relevant evidence
- Timeline
- Indicators
- Actions already performed
- ATT&CK mapping
- Current hypothesis
- Remaining questions

## 11. Lessons Learned

Record:

- What worked?
- What evidence was missing?
- What could improve detection?
- What could improve triage?
