#!/usr/bin/env python3

import argparse
import csv
import hashlib
import json
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlparse


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def addresses(message, header):
    value = message.get(header)
    if value is None:
        return []
    return [str(a) for a in value.addresses]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("email")
    parser.add_argument("--json", required=True)
    parser.add_argument("--iocs", required=True)
    args = parser.parse_args()

    source = Path(args.email)
    with source.open("rb") as f:
        message = BytesParser(policy=policy.default).parse(f)

    body_part = message.get_body(preferencelist=("plain",))
    body = body_part.get_content() if body_part else ""

    urls = re.findall(r"https?://[^\s<>]+", body)
    domains = sorted({
        urlparse(url).hostname
        for url in urls
        if urlparse(url).hostname
    })

    auth = str(message.get("Authentication-Results", ""))
    auth_results = {
        "spf": re.search(r"\bspf=([^\s;]+)", auth).group(1)
        if re.search(r"\bspf=([^\s;]+)", auth) else "unknown",
        "dkim": re.search(r"\bdkim=([^\s;]+)", auth).group(1)
        if re.search(r"\bdkim=([^\s;]+)", auth) else "unknown",
        "dmarc": re.search(r"\bdmarc=([^\s;]+)", auth).group(1)
        if re.search(r"\bdmarc=([^\s;]+)", auth) else "unknown",
    }

    record = {
        "evidence_type": "SYNTHETIC / CONTROLLED LAB",
        "source_file": source.as_posix(),
        "source_sha256": sha256_file(source),
        "date": str(message.get("Date", "")),
        "message_id": str(message.get("Message-ID", "")),
        "subject": str(message.get("Subject", "")),
        "from": addresses(message, "From"),
        "reply_to": addresses(message, "Reply-To"),
        "to": addresses(message, "To"),
        "return_path": str(message.get("Return-Path", "")),
        "received": [str(v) for v in message.get_all("Received", [])],
        "received_count": len(message.get_all("Received", [])),
        "authentication_results_raw": auth,
        "authentication": auth_results,
        "urls": urls,
        "url_domains": domains,
        "attachments": [],
        "limitations": [
            "Synthetic controlled-lab email; not production telemetry.",
            "Authentication-Results is retained scenario evidence, not independently validated mail-server runtime.",
            "No live URL request is performed by this parser.",
            "No reputation result is inferred from absence of evidence."
        ],
    }

    Path(args.json).write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    rows = []
    for url in urls:
        rows.append([
            url,
            "URL",
            source.as_posix(),
            str(message.get("Date", "")),
            "Message body",
            "High",
            "Not enriched",
            "Pending analyst assessment",
            "Synthetic reserved-domain indicator; no live request performed",
        ])

    for domain in domains:
        rows.append([
            domain,
            "Domain",
            source.as_posix(),
            str(message.get("Date", "")),
            "URL hostname",
            "High",
            "Not enriched",
            "Pending analyst assessment",
            "Synthetic reserved-domain indicator; no reputation inference",
        ])

    with Path(args.iocs).open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Indicator",
            "Type",
            "Source evidence",
            "First observed time",
            "Context",
            "Confidence",
            "Enrichment source and time",
            "Disposition",
            "Limitations",
        ])
        writer.writerows(rows)


if __name__ == "__main__":
    main()
