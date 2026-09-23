# Reproduce bounded SOC artifacts

Prerequisites: Python 3.12 (CI), Python 3.10+ for the local utilities, Bash, Git, isolated Python environment with `pysigma==0.11.23` (includes YAML support). Run from repository root. No Windows endpoint, SIEM backend or cloud credentials are used by these local tests.

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

Expected: positive/negative fixture assertions, rule parsing, integrity and byte-for-byte SOC-2026-004 timeline tests pass. Inspect failure output rather than changing expected results to force PASS. Inputs are versioned fixtures and the limited Linux excerpt; the test suite contains artificial controls.

The [004 validation guide](07-lab/detection-tests/SOC-2026-004/README.md) documents timeline regeneration and custom KQL tables. Tests do not execute a Sigma backend or KQL engine, prove production detection efficacy, or create real Windows evidence. Remote GitHub Actions for this remediation has not run. Delete only the disposable `.venv` you created when finished; do not remove source evidence. Capture tool versions, commit, commands, exit codes and stdout privately before publishing reviewed validation records.

Real Windows: [pending retained evidence gate](07-lab/WINDOWS_PENDING.md). KQL: [pending runtime gate](04-detection-rules/kql/README.md).
