from pathlib import Path
from sigma.collection import SigmaCollection

root = Path("04-detection-rules/sigma")
rules = sorted(list(root.rglob("*.yml")) + list(root.rglob("*.yaml")))

if not rules:
    raise SystemExit("ERROR: no Sigma rules found")

for rule in rules:
    SigmaCollection.from_yaml(rule.read_text())
    print(f"PASS: {rule}")

print(f"Sigma validation passed: {len(rules)} rule(s).")
