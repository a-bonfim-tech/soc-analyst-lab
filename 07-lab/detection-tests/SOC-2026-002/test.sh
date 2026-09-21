#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import csv
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

dataset = Path("10-evidence/SOC-2026-002/signinlogs-synthetic.csv")
kql = Path(
    "04-detection-rules/kql/SOC-2026-002/"
    "repeated-failures-followed-by-success.kql"
)

assert dataset.is_file(), "FAIL: synthetic SigninLogs dataset missing"
assert kql.is_file(), "FAIL: KQL detection file missing"

with dataset.open(newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def detect(source_rows):
    events = defaultdict(list)

    for row in source_rows:
        key = (row["UserPrincipalName"], row["IPAddress"])
        events[key].append(
            {
                "time": parse_time(row["TimeGenerated"]),
                "result": row["ResultType"],
                "app": row["AppDisplayName"],
            }
        )

    qualifying = []

    for (user, ip), values in events.items():
        values.sort(key=lambda event: event["time"])

        successes = [
            event for event in values
            if event["result"] == "0"
        ]

        for success in successes:
            window_start = success["time"] - timedelta(minutes=5)

            failures = [
                event["time"]
                for event in values
                if event["result"] != "0"
                and window_start <= event["time"] <= success["time"]
            ]

            if len(failures) >= 5:
                qualifying.append(
                    {
                        "user": user,
                        "ip": ip,
                        "count": len(failures),
                        "first_failure": min(failures),
                        "last_failure": max(failures),
                        "success_time": success["time"],
                        "success_app": success["app"],
                    }
                )

    earliest_by_key = {}

    for detection in qualifying:
        key = (detection["user"], detection["ip"])

        if (
            key not in earliest_by_key
            or detection["success_time"]
            < earliest_by_key[key]["success_time"]
        ):
            earliest_by_key[key] = detection

    return sorted(
        earliest_by_key.values(),
        key=lambda detection: detection["success_time"],
    )


detections = detect(rows)

assert len(detections) == 1, (
    f"FAIL: expected exactly 1 detection, got {len(detections)}"
)

detection = detections[0]

assert detection["user"] == "alex.meyer@contoso-lab.example"
assert detection["ip"] == "203.0.113.77"
assert detection["count"] == 6
assert detection["success_time"] == parse_time("2026-09-21T20:33:01Z")
assert detection["success_app"] == "Azure Portal"

# Regression case:
# an earlier successful sign-in from the same user/IP must not suppress
# detection of a later failure burst followed by a qualifying success.
edge_rows = list(rows)

edge_rows.append(
    {
        "TimeGenerated": "2026-09-21T20:00:00Z",
        "UserPrincipalName": "alex.meyer@contoso-lab.example",
        "UserDisplayName": "Alex Meyer",
        "IPAddress": "203.0.113.77",
        "Location": "NL",
        "AppDisplayName": "Azure Portal",
        "ResultType": "0",
        "ResultDescription": "Success",
        "IsInteractive": "true",
        "IsRisky": "false",
        "RiskEventTypes_V2": "",
    }
)

edge_detections = detect(edge_rows)

assert len(edge_detections) == 1, (
    "FAIL: earlier success incorrectly suppressed later detection"
)

edge_detection = edge_detections[0]

assert edge_detection["success_time"] == parse_time(
    "2026-09-21T20:33:01Z"
)
assert edge_detection["count"] == 6

print("PASS: dataset loaded")
print("PASS: KQL artifact exists")
print("PASS: exactly one qualifying sequence detected")
print("PASS: Alex/203.0.113.77 detected with 6 failures")
print("PASS: isolated failure scenarios were excluded")
print("PASS: earlier success does not suppress later qualifying sequence")
PY
