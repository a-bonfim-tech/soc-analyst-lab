# Reproduce bounded SOC artifacts

Prerequisites: Python 3.12 (CI), Python 3.10+ for the local utilities, Bash and Git. The parser-only validation suite uses the isolated dependency set in `requirements-dev.txt`; Sigma backend translation uses the separate pinned environment in `requirements-sigma-backend.txt`. Run from repository root. Neither local validation path requires a Windows endpoint, KQL engine or cloud credentials.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -B -m unittest discover -s tests -v
python -B 06-scripts/validate_sigma.py
python -B 06-scripts/validate_portfolio.py
bash 07-lab/detection-tests/SOC-2026-001/test.sh
bash 07-lab/detection-tests/SOC-2026-001-sigma/test.sh
bash 07-lab/detection-tests/SOC-2026-002/test.sh
```

Reproduce the retained SOC-2026-004 Sigma backend translation separately:

```sh
python3 -m venv /tmp/sigma-backend-validation
/tmp/sigma-backend-validation/bin/python -m pip install \
  -r requirements-sigma-backend.txt
/tmp/sigma-backend-validation/bin/python -B \
  06-scripts/validate_sigma_backend_translation.py
```

This second environment verifies the pinned `KustoBackend` /
`microsoft_xdr_pipeline()` translation output and the expected enriched-admin
translation failure. It does not execute KQL or contact Microsoft Defender
XDR, Microsoft Sentinel or Azure Data Explorer.

Expected: positive/negative fixture assertions, rule parsing, integrity and byte-for-byte SOC-2026-004 timeline tests pass. Inspect failure output rather than changing expected results to force PASS. Inputs are versioned fixtures and the limited Linux excerpt; the test suite contains artificial controls.

The [004 validation guide](07-lab/detection-tests/SOC-2026-004/README.md) documents timeline regeneration, custom KQL tables and the retained Sigma backend translation exercise. The repository unit-test evaluator itself does not execute a Sigma backend or KQL engine, prove production detection efficacy, or create real Windows evidence. Separately retained SOC-2026-004 evidence records KustoBackend/Microsoft XDR pipeline translation for the PowerShell and Registry rules, a limited read-only ADX/Kusto semantic PASS for the PowerShell translation, a confirmed semantic mismatch for the Registry translation, and an enrichment-related translation block for the admin rule. This is not Microsoft Defender XDR or Microsoft Sentinel runtime evidence. Remote validation was observed for hardening commit `954395381a8654eadf16fd5be7f3ee16dc39725e`: [completed PR run](https://github.com/a-bonfim-tech/soc-analyst-lab/actions/runs/35917284472). This does not validate later revisions; inspect their matching completed runs. Delete only the disposable `.venv` you created when finished; do not remove source evidence. Capture tool versions, commit, commands, exit codes and stdout privately before publishing reviewed validation records.

Real Windows: [retained endpoint telemetry status](07-lab/WINDOWS_STATUS.md). KQL: [runtime evidence status and gate](04-detection-rules/kql/README.md).
