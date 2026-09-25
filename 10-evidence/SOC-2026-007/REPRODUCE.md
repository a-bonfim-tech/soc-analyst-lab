# SOC-2026-007 — Reproduction

## Scope

These instructions reproduce the deterministic extraction and local validation of the synthetic phishing investigation evidence.

They do not reproduce a production mail server, production email-security platform, real victim interaction or external reputation lookup.

## Requirements

- Python 3
- POSIX-compatible shell
- repository checkout containing SOC-2026-007
- no network access required

## Primary evidence

`10-evidence/SOC-2026-007/suspicious-email.eml`

## Parser

`06-scripts/SOC-2026-007/parse_email_evidence.py`

## Reproduce derived metadata

Run:

`python3 06-scripts/SOC-2026-007/parse_email_evidence.py 10-evidence/SOC-2026-007/suspicious-email.eml --json 10-evidence/SOC-2026-007/derived/email-metadata.json --iocs 10-evidence/SOC-2026-007/derived/ioc-register.csv`

## Validate parser syntax

Run:

`python3 -m py_compile 06-scripts/SOC-2026-007/parse_email_evidence.py`

## Validate repository whitespace

Run:

`git diff --check`

## Expected evidence properties

The retained message should produce:

- two Received headers;
- one body URL;
- zero attachments;
- retained scenario SPF result `pass`;
- retained scenario DKIM result `none`;
- retained scenario DMARC result `fail`.

These authentication values are parsed from the synthetic retained message. They are not independently validated production DNS or mail-server results.

## Safety

Do not browse the synthetic URL.

Do not replace reserved laboratory indicators with live malicious infrastructure.

No external enrichment is required to reproduce this case.

## Candidate commit

Final repository validation must be performed against the exact candidate commit after explicit staging and commit creation.

Until that step is completed, exact candidate-commit validation remains pending.
