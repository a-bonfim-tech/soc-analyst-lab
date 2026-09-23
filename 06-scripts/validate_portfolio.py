"""Basic portfolio integrity and high-confidence sensitive-pattern checks."""
import ast
import csv
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote
import yaml

ROOT = Path(__file__).resolve().parents[1]


def validate():
    names = subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'], cwd=ROOT).decode().split('\0')
    files = sorted({ROOT/name for name in names if name})
    required = [
        '02-datasets/soc-2026-004/windows-security-events.csv',
        '02-datasets/soc-2026-004/sysmon-events.json',
        '02-datasets/soc-2026-004/asset-context.json',
        '02-datasets/soc-2026-004/README.md',
        '03-investigations/SOC-2026-004/investigation.md',
        '03-investigations/SOC-2026-004/timeline.csv',
        '03-investigations/SOC-2026-004/findings.md',
        '03-investigations/SOC-2026-004/escalation.md',
        '04-detection-rules/ATTACK-COVERAGE.md',
        '05-automation/build_timeline.py', 'tests/test_soc004.py',
        '07-lab/detection-tests/SOC-2026-004/README.md']
    for kind in ['sigma','kql']:
        for rule in ['suspicious-powershell','unusual-admin-logon','registry-run-key-persistence']:
            required.append(f'04-detection-rules/{kind}/SOC-2026-004/{rule}.'+('yml' if kind=='sigma' else 'kql'))
    errors=[]
    for name in required:
        if not (ROOT/name).is_file() or not (ROOT/name).stat().st_size:
            errors.append(f'missing/empty: {name}')
    patterns = [r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
                r'(?:THM|HTB)\{[^}\r\n]{4,}\}',
                r'gh[pousr]_[A-Za-z0-9]{30,}',r'AKIA[0-9A-Z]{16}',
                r'(?im)^\s*(?:password|api_key|auth_token|vpn_password)\s*[:=]\s*["\']?[^\s"\']{8,}']
    for path in files:
        if path.suffix not in {'.md','.py','.sh','.csv','.json','.yml','.yaml','.kql','.txt','.log'}:
            continue
        text=path.read_text(encoding='utf-8')
        if any(re.search(pattern,text) for pattern in patterns):
            errors.append(f'sensitive pattern: {path.relative_to(ROOT)}')
        if path.suffix=='.py': ast.parse(text,filename=str(path))
        if path.suffix=='.json': json.loads(text)
        if path.suffix in {'.yml','.yaml'}: yaml.safe_load(text)
        if path.suffix=='.md':
            if not text.startswith('# ') or not text.endswith('\n'):
                errors.append(f'Markdown title/newline: {path.relative_to(ROOT)}')
            if sum(line.startswith('```') for line in text.splitlines()) % 2:
                errors.append(f'unclosed code fence: {path.relative_to(ROOT)}')
            for target in re.findall(r'(?<!!)\[[^\]]+\]\(([^)]+)\)',text):
                if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:',target) or target.startswith('#'):
                    continue
                dest=unquote(target.split('#')[0])
                if dest and not (path.parent/dest).exists():
                    errors.append(f'broken link in {path.relative_to(ROOT)}: {dest}')
    if errors:
        raise ValueError('\n'.join(errors))
    print(f'PASS: {len(required)} required artifacts; repository syntax, JSON/YAML, basic Markdown/local paths and sensitive-pattern scan ({len(files)} files).')


if __name__=='__main__':
    validate()
