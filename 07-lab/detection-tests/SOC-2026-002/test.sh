#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import csv
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

dataset = Path("10-evidence/SOC-2026-002/signinlogs-synthetic.csv")
kql = Path(
    "04-detection-rules/kql/SOC-2026-002/"
    "repeated-failures-followed-by-success.kql"
)

assert dataset.is_file(), "FAIL: synthetic SigninLogs dataset missing"
assert kql.is_file(), "FAIL: KQL detection file missing"

with dataset.open(newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

events = defaultdict(list)

for row in rows:
    ts = datetime.fromisoformat(
        row["TimeGenerated"].replace("Z", "+00:00")
    )
    key = (row["UserPrincipalName"], row["IPAddress"])
    events[key].append((ts, row["ResultType"]))

detections = []

for (user, ip), values in events.items():
    values.sort()

    failures = [ts for ts, result in values if result != "0"]
    successes = [ts for ts, result in values if result == "0"]

    if len(failures) < 5 or not successes:
        continue

    first_failure = min(failures)
    last_failure = max(failures)
    first_success = min(successes)

    if last_failure <= first_success <= last_failure + timedelta(minutes=5):
        detections.append(
            (user, ip, len(failures), first_failure, last_failure, first_success)
        )

assert len(detections) == 1, (
    f"FAIL: expected exactly 1 detection, got {len(detections)}"
)

user, ip, count, first_failure, last_failure, first_success = detections[0]

assert user == "alex.meyer@contoso-lab.example"
assert ip == "203.0.113.77"
assert count == 6

print("PASS: dataset loaded")
print("PASS: KQL artifact exists")
print("PASS: exactly one failure-followed-by-success sequence detected")
print("PASS: Alex/203.0.113.77 detected with 6 failures")
print("PASS: benign-style isolated failures were excluded")
PY
