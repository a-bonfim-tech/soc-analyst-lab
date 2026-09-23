"""Fixture regression tests; NOT a Sigma backend or KQL execution engine."""
import copy
import csv
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / '02-datasets/soc-2026-004'
RULES = ROOT / '04-detection-rules/sigma/SOC-2026-004'
SCRIPT = ROOT / '05-automation/build_timeline.py'
spec = importlib.util.spec_from_file_location('timeline', SCRIPT)
tl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tl)


def match_selection(rule, event):
    """Evaluate this suite's single AND selection, OR lists and three string modifiers.

    Reads the actual YAML selection to catch rule/fixture drift. Rejects unsupported
    syntax. This narrow evaluator does not validate backend translation or ingestion.
    """
    detection = rule['detection']
    if set(detection) != {'selection', 'condition'} or detection['condition'] != 'selection':
        raise ValueError('unsupported condition')
    for key, expected in detection['selection'].items():
        parts = key.split('|')
        if len(parts) > 2:
            raise ValueError('unsupported modifiers')
        field = parts[0]
        modifier = parts[1] if len(parts) == 2 else 'equals'
        if modifier not in {'equals','endswith','contains'}:
            raise ValueError('unsupported modifier')
        if field not in event or event[field] is None:
            return False
        actual = event[field]
        options = expected if isinstance(expected, list) else [expected]
        def compare(value):
            if modifier == 'equals':
                if isinstance(value, bool):
                    return isinstance(actual, bool) and actual == value
                return str(actual).casefold() == str(value).casefold()
            if not isinstance(actual, str) or not isinstance(value, str):
                return False
            a, b = actual.casefold(), value.casefold()
            return a.endswith(b) if modifier == 'endswith' else b in a
        if not any(compare(value) for value in options):
            return False
    return True


def enrich(event, context):
    event = dict(event)
    if event['Computer'] == context['hostname']:
        event['PrivilegedAccount'] = event['Account'] in context['privileged_accounts']
        if event.get('IpAddress'):
            event['SourceApproved'] = event['IpAddress'] in context['expected_admin_sources']
    return event


class Detections(unittest.TestCase):
    def setUp(self):
        self.sec, self.sys = tl.read_evidence(DATA/'windows-security-events.csv', DATA/'sysmon-events.json')
        self.context = json.loads((DATA/'asset-context.json').read_text())
        self.rules = {p.stem:yaml.safe_load(p.read_text()) for p in RULES.glob('*.yml')}

    def test_schema_and_sigma_parser(self):
        self.assertEqual(len(self.rules), 3)
        required = {'title','id','status','description','author','date','references','logsource','detection','falsepositives','level','tags'}
        ids = set()
        for path in RULES.glob('*.yml'):
            rule = yaml.safe_load(path.read_text())
            self.assertTrue(required <= rule.keys())
            self.assertNotIn(rule['id'], ids)
            ids.add(rule['id'])
            SigmaCollection.from_yaml(path.read_text())
        self.assertTrue(self.context['synthetic'])
        self.assertEqual((len(self.sec), len(self.sys)), (13,10))

    def test_expected_hits_and_benign_controls(self):
        events = self.sys + [enrich(row,self.context) for row in self.sec]
        expected = {'suspicious-powershell':['SYS-005'], 'unusual-admin-logon':['SEC-009'],
                    'registry-run-key-persistence':['SYS-007']}
        for name, rule in self.rules.items():
            self.assertEqual([row['RecordId'] for row in events if match_selection(rule,row)], expected[name])

    def test_powershell_variants(self):
        rule = self.rules['suspicious-powershell']
        row = dict(self.sys[4], Image=r'D:\Tools\pwsh.exe', ParentImage=r'C:\Office\EXCEL.EXE',
                   CommandLine='pwsh.exe -ENC harmless')
        self.assertTrue(match_selection(rule,row))
        for field, value in [('EventID',3), ('Image',r'C:\Tools\fakepowershell.exe'),
                             ('ParentImage',r'C:\Windows\explorer.exe'), ('CommandLine','powershell.exe -File ok.ps1')]:
            self.assertFalse(match_selection(rule,dict(row,**{field:value})))

    def test_admin_context_boundaries(self):
        rule = self.rules['unusual-admin-logon']
        row = self.sec[8]
        self.assertFalse(match_selection(rule,row))
        self.assertTrue(match_selection(rule,enrich(row,self.context)))
        for field,value in [('Computer','other-host'),('IpAddress',''),('IpAddress','192.0.2.10'),
                            ('Account','SYNTH\\lee'),('LogonType','3'),('EventID','4625')]:
            self.assertFalse(match_selection(rule,enrich(dict(row,**{field:value}),self.context)))
        # New source still detects: behavior is not tied to the positive fixture IP.
        self.assertTrue(match_selection(rule,enrich(dict(row,IpAddress='198.51.100.99'),self.context)))

    def test_registry_boundaries(self):
        rule = self.rules['registry-run-key-persistence']
        row = dict(self.sys[6], Details=r'"C:\Users\other\AppData\Roaming\other.exe"')
        self.assertTrue(match_selection(rule,row))
        for field,value in [('EventID',12),('Details',r'C:\Program Files\Vendor\ok.exe'),
                            ('Details',r'C:\Users\Public\note.txt'),
                            ('TargetObject',r'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\Item')]:
            self.assertFalse(match_selection(rule,dict(row,**{field:value})))

    def test_synthetic_network_and_script_consistency(self):
        import base64
        import ipaddress
        nets = [ipaddress.ip_network(n) for n in ['192.0.2.0/24','198.51.100.0/24','203.0.113.0/24']]
        addresses = [e['IpAddress'] for e in self.sec if e['IpAddress']]
        addresses += [e['DestinationIp'] for e in self.sys if e['DestinationIp']]
        self.assertTrue(all(any(ipaddress.ip_address(a) in n for n in nets) for a in addresses))
        script = base64.b64decode(self.sys[4]['CommandLine'].split()[-1],validate=True).decode('utf-16le')
        self.assertIn(self.sys[5]['DestinationIp'],script)
        self.assertIn(self.sys[6]['Details'],script)
        self.assertIn('New-ItemProperty',script)
        self.assertEqual(self.sys[4]['ProcessGuid'], self.sys[5]['ProcessGuid'])
        self.assertEqual(self.sys[4]['ProcessGuid'], self.sys[6]['ProcessGuid'])

    def test_evaluator_rejects_unsupported_logic(self):
        rule = copy.deepcopy(self.rules['suspicious-powershell'])
        rule['detection']['condition'] = 'selection or other'
        with self.assertRaises(ValueError):
            match_selection(rule,self.sys[4])


class Timeline(unittest.TestCase):
    def setUp(self):
        self.sec = DATA/'windows-security-events.csv'
        self.sys = DATA/'sysmon-events.json'

    def test_order_count_and_committed_reproducibility(self):
        rows = tl.build(self.sec,self.sys)
        self.assertEqual(len(rows),23)
        self.assertEqual([r['timestamp'] for r in rows],sorted(r['timestamp'] for r in rows))
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)/'timeline.csv'
            tl.write_timeline(rows,out)
            self.assertEqual(out.read_bytes(),(ROOT/'03-investigations/SOC-2026-004/timeline.csv').read_bytes())

    def test_evidence_preserved_and_correlations(self):
        rows = tl.build(self.sec,self.sys)
        sec,sysm = tl.read_evidence(self.sec,self.sys)
        self.assertEqual({r['record_id']:json.loads(r['evidence']) for r in rows},
                         {e['RecordId']:e for e in sec+sysm})
        index = {r['record_id']:r for r in rows}
        self.assertIn('Security:SEC-010',index['SEC-009']['related_records'])
        self.assertIn('Sysmon:SYS-005',index['SEC-009']['related_records'])
        self.assertIn('Sysmon:SYS-007',index['SYS-006']['related_records'])
        self.assertNotIn('SEC-003',index['SEC-009']['related_records'])
        self.assertTrue(all(r['attack_technique']=='' for r in rows))

    def test_timezone_and_missing_timezone(self):
        self.assertEqual(tl.timestamp('2026-09-23T11:00:00+02:00'),tl.timestamp('2026-09-23T09:00:00Z'))
        with self.assertRaises(ValueError): tl.timestamp('2026-09-23T09:00:00')

    def test_input_order_and_host_isolation(self):
        events = json.loads(self.sys.read_text())
        events[5]['Computer'] = 'OTHER'
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'sys.json';p.write_text(json.dumps(list(reversed(events))))
            rows=tl.build(self.sec,p)
            row=next(r for r in rows if r['record_id']=='SYS-006')
            self.assertEqual(row['related_records'],'')
            events[5]['Computer']='SYN-WIN-04'
            p.write_text(json.dumps(list(reversed(events))))
            self.assertEqual(tl.build(self.sec,p),tl.build(self.sec,self.sys))

    def test_bad_inputs_do_not_replace_output(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); bad=d/'bad.json'; out=d/'out.csv';out.write_text('preserve')
            for contents in ['{', '{}', '[]', '[{}]']:
                bad.write_text(contents)
                run=subprocess.run([sys.executable,str(SCRIPT),'--security-events',str(self.sec),
                                    '--sysmon',str(bad),'--output',str(out)],capture_output=True)
                self.assertEqual(run.returncode,2)
                self.assertEqual(out.read_text(),'preserve')

    def test_duplicate_and_csv_schema(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bad.json';events=json.loads(self.sys.read_text());events.append(events[0]);p.write_text(json.dumps(events))
            with self.assertRaises(ValueError): tl.build(self.sec,p)
            c=Path(d)/'bad.csv';c.write_text('RecordId\nSEC-001\n')
            with self.assertRaises(ValueError): tl.build(c,self.sys)

    def test_wrong_scalar_type_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bad.json';events=json.loads(self.sys.read_text())
            events[0]['UtcTime']=123
            p.write_text(json.dumps(events))
            with self.assertRaises(ValueError): tl.build(self.sec,p)

    def test_cli_success_and_source_protection(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'out.csv'
            cmd=[sys.executable,str(SCRIPT),'--security-events',str(self.sec),'--sysmon',str(self.sys),'--output']
            self.assertEqual(subprocess.run(cmd+[str(out)],capture_output=True).returncode,0)
            self.assertEqual(subprocess.run(cmd+[str(self.sec)],capture_output=True).returncode,2)


if __name__ == '__main__':
    unittest.main()
