# SOC Analyst Lab

Hands-on Security Operations Center (SOC) training laboratory focused on developing practical Tier 1 SOC Analyst skills through alert triage, log analysis, incident investigation, detection engineering, threat intelligence, and documented escalation workflows.

## Objectives

This laboratory is designed to develop practical capability in:

- Security alert triage
- SIEM investigation
- Windows and Linux log analysis
- Authentication monitoring
- Network security monitoring
- Endpoint telemetry analysis
- IOC analysis and enrichment
- Phishing investigation
- Threat intelligence
- MITRE ATT&CK mapping
- Incident severity assessment
- False-positive analysis
- Escalation to Tier 2
- SOC reporting
- Detection engineering
- Defensive automation

## Lab Environment

Current components:

- macOS analyst workstation
- Kali Linux adversary-simulation workstation
- Git and GitHub for version-controlled documentation
- TryHackMe for guided SOC training
- MITRE ATT&CK for behavioral mapping
- ChatGPT for investigation exercises and analyst training
- Codex for defensive automation and repository engineering

Planned components:

- SIEM/XDR platform
- Linux monitored endpoint
- Centralized telemetry collection
- Controlled attack simulation
- Detection rules
- Real log-based investigations

## Repository Structure

    00-governance/
        Lab scope, policies, evidence handling, and training objectives.

    01-runbooks/
        SOC procedures and investigation playbooks.

    02-alerts/
        Sanitized security alerts used for triage exercises.

    03-investigations/
        Documented SOC investigations and escalation packages.

    04-detection-rules/
        Detection rules, SIEM queries, and detection engineering artifacts.

    05-threat-intelligence/
        IOC research, threat analysis, and ATT&CK mappings.

    06-scripts/
        Defensive automation and SOC utility scripts.

    07-lab/
        Laboratory architecture and infrastructure documentation.

    08-tryhackme/
        Sanitized training notes and learning records.

    09-reports/
        Incident reports and SOC handover documentation.

    10-evidence/
        Sanitized evidence suitable for version control.

## Investigation Methodology

Investigations follow an evidence-driven workflow:

    Alert
      ↓
    Validation
      ↓
    Context Collection
      ↓
    Evidence
      ↓
    Timeline
      ↓
    Hypothesis
      ↓
    MITRE ATT&CK Mapping
      ↓
    Disposition
      ↓
    Severity Assessment
      ↓
    Close or Escalate

A central principle of this laboratory is to distinguish:

- observed fact;
- analytical inference;
- investigative hypothesis;
- confirmed conclusion.

An alert alone is not treated as proof of malicious activity.

## Completed Investigations

### SOC-2026-001 — SSH Authentication Investigation

Scenario involving repeated SSH authentication failures followed by successful authentication and privileged activity.

Tier 1 activities included:

- alert validation;
- authentication-log analysis;
- asset and account context analysis;
- timeline reconstruction;
- privilege-related event analysis;
- MITRE ATT&CK mapping;
- severity reassessment;
- Tier 2 escalation.

Final Tier 1 status:

**Escalated to Tier 2 — suspicious activity, authorization pending.**

See:

`03-investigations/SOC-2026-001/`

## MITRE ATT&CK

MITRE ATT&CK is used to map observed behaviors to relevant tactics and techniques.

Mappings are treated as behavioral classifications and do not independently establish malicious intent.

## Evidence Handling

Raw credentials, secrets, authentication tokens, private evidence, memory dumps, sensitive packet captures, and other confidential artifacts must not be committed to this repository.

Only synthetic, sanitized, or explicitly approved evidence should be version controlled.

## Training Principle

The objective is not simply to complete security exercises.

The objective is to demonstrate a repeatable SOC workflow:

**detect → validate → investigate → document → decide → escalate or close.**

Automation is introduced only after the underlying analyst workflow is understood manually.

## Status

Active development.

Current stage:

**Tier 1 foundations and SOC laboratory infrastructure.**
