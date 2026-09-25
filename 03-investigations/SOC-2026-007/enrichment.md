# SOC-2026-007 — Controlled Enrichment Record

## Evidence state

SYNTHETIC / CONTROLLED LAB.

## Purpose

Record enrichment decisions without converting synthetic indicators into unsupported real-world reputation claims.

## Indicators

### URL

Indicator:

`https://invoice-review.example/review/SOC-2026-007`

Source:

Retained message body.

Analytical context:

The URL is presented as an invoice-review destination.

Enrichment state:

`NOT APPLICABLE — RESERVED SYNTHETIC DOMAIN`

No live request was performed.

No malicious, benign or neutral reputation score is assigned.

### Domain

Indicator:

`invoice-review.example`

Source:

Derived mechanically from the retained URL.

Enrichment state:

`NOT APPLICABLE — RESERVED SYNTHETIC DOMAIN`

The `.example` namespace is being used for controlled laboratory evidence.

No real-world domain ownership or reputation is inferred.

### Transport addresses

The retained `Received` chain contains documentation-range IP addresses.

Enrichment state:

`NOT APPLICABLE — DOCUMENTATION ADDRESSES`

No geolocation, ASN ownership, abuse reputation or threat-intelligence conclusion is assigned to those synthetic addresses.

## Sender-domain relationship

FACT:

Visible `From` domain:

`corp-lab.example`

Reply-To domain:

`mailer-lab.example`

Envelope return domain:

`mailer-lab.example`

DERIVED:

The reply and envelope domains differ from the visible author domain.

FACT:

The retained scenario records SPF pass for `mailer-lab.example`, DKIM none and DMARC fail for `corp-lab.example`.

ASSESSMENT:

The domain mismatch plus DMARC failure increases suspicion in this scenario, but does not independently prove malicious sender intent.

## Reputation

UNKNOWN / NOT APPLICABLE TO SYNTHETIC INDICATORS.

No VirusTotal, URLhaus, WHOIS, RDAP, passive DNS, ASN or commercial threat-intelligence result is claimed.

A zero-result or fabricated reputation lookup would not constitute useful evidence for reserved laboratory indicators.

## User-impact enrichment

No click telemetry, proxy telemetry, DNS telemetry, endpoint telemetry, identity telemetry or mailbox-wide search results are retained.

Therefore:

- URL click: UNKNOWN;
- credential submission: UNKNOWN;
- endpoint execution: UNKNOWN;
- account compromise: UNKNOWN;
- additional recipients: UNKNOWN.

## Analyst conclusion from enrichment

Controlled enrichment does not establish malicious infrastructure or successful compromise.

It preserves the principal suspicious evidence:

- finance-themed urgency;
- sender/reply-domain mismatch;
- envelope-domain mismatch;
- DMARC failure;
- absent DKIM result;
- embedded review URL.

Final severity and disposition must therefore depend on the email evidence and explicitly limited impact evidence, not on invented external reputation.
