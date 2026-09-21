#!/usr/bin/env bash
set -euo pipefail

real="10-evidence/SOC-2026-001/real-lab-auth.txt"
negative="07-lab/detection-tests/SOC-2026-001/negative.log"

grep -F '/etc/shadow' "$real" >/dev/null

if grep -F '/etc/shadow' "$negative" >/dev/null; then
  echo "FAIL: benign fixture unexpectedly matched."
  exit 1
fi

echo "PASS: real telemetry matched /etc/shadow detection."
echo "PASS: benign fixture did not match."
