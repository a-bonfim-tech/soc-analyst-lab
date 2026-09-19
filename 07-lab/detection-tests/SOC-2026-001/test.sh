#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

positive="${script_dir}/positive.log"
negative="${script_dir}/negative.log"

detect_shadow_access() {
  local file="$1"

  grep -F 'sudo[' "$file" |
    grep -F 'USER=root' |
    grep -F 'COMMAND=' |
    grep -F '/etc/shadow'
}

echo "=== POSITIVE TEST ==="

set +e
positive_output="$(detect_shadow_access "$positive")"
positive_rc=$?
set -e

if [[ "$positive_rc" -ne 0 ]]; then
  echo "FAIL: expected positive fixture to match."
  exit 1
fi

printf '%s\n' "$positive_output"
echo "PASS: positive fixture matched."

echo
echo "=== NEGATIVE TEST ==="

set +e
negative_output="$(detect_shadow_access "$negative")"
negative_rc=$?
set -e

if [[ "$negative_rc" -eq 0 ]]; then
  echo "FAIL: expected negative fixture not to match."
  printf '%s\n' "$negative_output"
  exit 1
fi

if [[ "$negative_rc" -ne 1 ]]; then
  echo "FAIL: detector returned unexpected exit code: $negative_rc"
  exit 1
fi

echo "PASS: negative fixture did not match."

echo
echo "PASS: detection hypothesis tests completed successfully."
