#!/usr/bin/env python3
"""Reproduce retained SOC-2026-004 Sigma backend translation evidence.

This validator checks deterministic backend translation only.

It does not:
- execute Microsoft Defender XDR;
- execute Microsoft Sentinel;
- execute Azure Data Explorer / Kusto semantic tests;
- make production detection-efficacy claims.
"""

from __future__ import annotations

import hashlib
import json
from importlib.metadata import version
from pathlib import Path

from sigma.backends.kusto.kusto import KustoBackend
from sigma.exceptions import SigmaTransformationError
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.rule import SigmaRule


ROOT = Path(__file__).resolve().parents[1]

EVIDENCE_DIR = (
    ROOT
    / "10-evidence"
    / "SOC-2026-004"
    / "sigma-backend-translation"
)

RULE_DIR = (
    ROOT
    / "04-detection-rules"
    / "sigma"
    / "SOC-2026-004"
)

METADATA_PATH = EVIDENCE_DIR / "translation-metadata.json"

EXPECTED_PACKAGES = {
    "pysigma": "1.5.1",
    "pysigma-backend-kusto": "1.0.1",
}

TRANSLATED_RULES = {
    "suspicious-powershell.yml":
        "suspicious-powershell.generated.kql",
    "registry-run-key-persistence.yml":
        "registry-run-key-persistence.generated.kql",
}

BLOCKED_RULE = "unusual-admin-logon.yml"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_metadata() -> dict:
    with METADATA_PATH.open(
        "r",
        encoding="utf-8",
    ) as handle:
        return json.load(handle)


def verify_package_versions(metadata: dict) -> None:
    print("=== PACKAGE VERSIONS ===")

    for package, expected in EXPECTED_PACKAGES.items():
        actual = version(package)

        print(
            f"{package}: "
            f"expected={expected} actual={actual}"
        )

        if actual != expected:
            raise SystemExit(
                f"ERROR: unexpected {package} version"
            )

    env = metadata["translation_environment"]

    if env["pysigma"] != EXPECTED_PACKAGES["pysigma"]:
        raise SystemExit(
            "ERROR: metadata pySigma version mismatch"
        )

    if (
        env["pysigma_backend_kusto"]
        != EXPECTED_PACKAGES["pysigma-backend-kusto"]
    ):
        raise SystemExit(
            "ERROR: metadata Kusto backend version mismatch"
        )

    if env["pipeline"] != "microsoft_xdr_pipeline":
        raise SystemExit(
            "ERROR: unexpected metadata pipeline"
        )

    if env["backend"] != "KustoBackend":
        raise SystemExit(
            "ERROR: unexpected metadata backend"
        )

    print("PASS: package and metadata versions verified")


def verify_source_hash(
    rule_name: str,
    metadata: dict,
) -> bytes:
    path = RULE_DIR / rule_name
    data = path.read_bytes()

    expected = (
        metadata["rules"][rule_name]["source_sha256"]
    )

    actual = sha256_bytes(data)

    print(
        f"{rule_name}: "
        f"source_sha256={actual}"
    )

    if actual != expected:
        raise SystemExit(
            f"ERROR: source rule hash mismatch: {rule_name}"
        )

    return data


def translate_rule(rule_data: bytes) -> list[str]:
    rule = SigmaRule.from_yaml(
        rule_data.decode("utf-8")
    )

    backend = KustoBackend(
        processing_pipeline=microsoft_xdr_pipeline()
    )

    return backend.convert_rule(rule)


def verify_translated_rule(
    rule_name: str,
    retained_name: str,
    metadata: dict,
) -> None:
    print()
    print(f"=== TRANSLATE {rule_name} ===")

    source = verify_source_hash(
        rule_name,
        metadata,
    )

    record = metadata["rules"][rule_name]

    if record["translation_status"] != "BACKEND_TRANSLATED":
        raise SystemExit(
            f"ERROR: unexpected translation state: {rule_name}"
        )

    queries = translate_rule(source)

    if len(queries) != 1:
        raise SystemExit(
            f"ERROR: expected one query for {rule_name}, "
            f"got {len(queries)}"
        )

    emitted = queries[0]

    emitted_hash = sha256_bytes(
        emitted.encode("utf-8")
    )

    expected_emitted_hash = (
        record["generated_query_sha256"]
    )

    print(
        "generated_query_sha256: "
        f"{emitted_hash}"
    )

    if emitted_hash != expected_emitted_hash:
        raise SystemExit(
            f"ERROR: generated query hash mismatch: {rule_name}"
        )

    retained_path = EVIDENCE_DIR / retained_name
    retained_bytes = retained_path.read_bytes()

    retained_hash = sha256_bytes(retained_bytes)

    print(
        "retained_file_sha256: "
        f"{retained_hash}"
    )

    if retained_hash != record["retained_file_sha256"]:
        raise SystemExit(
            f"ERROR: retained evidence hash mismatch: {retained_name}"
        )

    if not retained_bytes.endswith(b"\n"):
        raise SystemExit(
            f"ERROR: retained query lacks terminal newline: "
            f"{retained_name}"
        )

    retained_query = retained_bytes[:-1].decode("utf-8")

    if retained_query != emitted:
        raise SystemExit(
            f"ERROR: emitted query differs from retained evidence: "
            f"{rule_name}"
        )

    print(
        f"PASS: {rule_name} reproduces retained backend query"
    )


def verify_blocked_rule(
    rule_name: str,
    metadata: dict,
) -> None:
    print()
    print(f"=== TRANSLATE {rule_name} ===")

    source = verify_source_hash(
        rule_name,
        metadata,
    )

    record = metadata["rules"][rule_name]

    if (
        record["translation_status"]
        != "BACKEND_TRANSLATION_BLOCKED_BY_ENRICHMENT"
    ):
        raise SystemExit(
            "ERROR: unexpected blocked-rule translation state"
        )

    if record["generated_query_sha256"] is not None:
        raise SystemExit(
            "ERROR: blocked rule unexpectedly has query hash"
        )

    if record["semantic_test_status"] != "NOT_APPLICABLE":
        raise SystemExit(
            "ERROR: blocked rule semantic status is not "
            "NOT_APPLICABLE"
        )

    expected_error = record["error_type"]
    blocking_field = record["blocking_field"]

    try:
        translate_rule(source)
    except SigmaTransformationError as exc:
        actual_error = type(exc).__name__
        message = str(exc)

        print(f"error_type: {actual_error}")
        print(f"blocking_field: {blocking_field}")

        if actual_error != expected_error:
            raise SystemExit(
                "ERROR: unexpected transformation error type"
            )

        if blocking_field not in message:
            raise SystemExit(
                "ERROR: expected blocking field absent from error"
            )

        print(
            "PASS: blocked translation state reproduced"
        )
        return

    raise SystemExit(
        "ERROR: blocked rule unexpectedly translated"
    )


def main() -> int:
    metadata = read_metadata()

    if metadata["case"] != "SOC-2026-004":
        raise SystemExit(
            "ERROR: unexpected evidence case"
        )

    if (
        metadata["evidence_type"]
        != "sigma_backend_translation"
    ):
        raise SystemExit(
            "ERROR: unexpected evidence type"
        )

    verify_package_versions(metadata)

    for rule_name, retained_name in TRANSLATED_RULES.items():
        verify_translated_rule(
            rule_name,
            retained_name,
            metadata,
        )

    verify_blocked_rule(
        BLOCKED_RULE,
        metadata,
    )

    print()
    print(
        "PASS: SOC-2026-004 SIGMA BACKEND "
        "TRANSLATION REPRODUCED"
    )
    print(
        "NOTE: translation reproducibility only; "
        "no KQL engine execution performed"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
