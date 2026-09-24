"""Artificial transient parser inputs only: never SOC-2026-003 endpoint evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('ingest_windows.py')
spec = importlib.util.spec_from_file_location('ingest', SCRIPT)
ingest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ingest)


def event(channel, eid, rid='1', timestamp='2026-01-01T00:00:01.1234567Z', payload=True):
    data = '<EventData><Data Name="Image">TEST-ONLY</Data><Data Name="Empty"></Data><Data>unnamed</Data></EventData>' if payload else ''
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="TEST-ONLY"/><EventID>{eid}</EventID><EventRecordID>{rid}</EventRecordID>'
            f'<TimeCreated SystemTime="{timestamp}"/><Computer>TEST-ONLY</Computer>'
            f'<Channel>{channel}</Channel></System>{data}</Event>')


def package(root):
    channels=[]
    for name,(channel,ids,required) in ingest.SOURCES.items():
        count = 1 if required else 0
        (root/(name+'.xml')).write_text('<Events>'+ (event(channel,min(ids)) if count else '') +'</Events>')
        channels.append(dict(name=name,channel=channel,event_ids=sorted(ids),required=required,
                             status='collected' if count else 'no_events',count=count,file=name+'.xml',error_code=None))
    meta=dict(schema_version=1,case_id='SOC-2026-003',phase='final',source_kind='Windows EventRecord.ToXml',
              authorized_disposable_lab=True,hostname='TEST-ONLY',collector='TEST-ONLY',os_version='TEST-ONLY',
              powershell_version='TEST-ONLY',local_timezone='UTC',collector_script_sha256='0'*64,
              requested_start_utc='2026-01-01T00:00:00Z',requested_end_utc='2026-01-01T00:01:00Z',
              collection_start_utc='2026-01-01T00:02:00Z',collection_end_utc='2026-01-01T00:03:00Z',
              required_sources_collected=True,channels=channels)
    (root/'metadata.json').write_text(json.dumps(meta))
    seal(root)
    return meta


def seal(root):
    files=[dict(name=p.name,bytes=p.stat().st_size,sha256=ingest.digest(p)) for p in sorted(root.iterdir())
           if p.name not in {'manifest.json','manifest.sha256'}]
    (root/'manifest.json').write_text(json.dumps(dict(schema_version=1,files=files)))
    (root/'manifest.sha256').write_text(ingest.digest(root/'manifest.json')+'  manifest.json\n')


class Ingestion(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'source';self.root.mkdir()
        self.meta=package(self.root)

    def update_meta(self):
        (self.root/'metadata.json').write_text(json.dumps(self.meta));seal(self.root)

    def cli(self,output):
        return subprocess.run([sys.executable,'-B',str(SCRIPT),'--input',str(self.root),'--output',str(output)],capture_output=True)

    def test_normalization_and_absence(self):
        rows,summary=ingest.verify_package(self.root)
        self.assertEqual(summary['event_count'],2)
        self.assertEqual(rows[0]['timestamp_utc'],'2026-01-01T00:00:01.1234567Z')
        self.assertEqual(rows[0]['timestamp_original'],rows[0]['timestamp_utc'])
        self.assertIsNone(rows[0]['event_data'][1]['value'])
        self.assertIsNone(rows[0]['event_data'][2]['name'])
        self.assertIsNone(rows[0]['user_data_xml'])
        p=self.root/'sysmon.xml';p.write_text('<Events>'+event(ingest.SOURCES['sysmon'][0],1,payload=False)+'</Events>');seal(self.root)
        rows,_=ingest.verify_package(self.root)
        self.assertIsNone(next(r for r in rows if r['event_id']==1)['event_data'])

    def test_offset_and_precision(self):
        self.assertEqual(ingest.stamp('2026-01-01T02:00:01.1234567+02:00'),'2026-01-01T00:00:01.1234567Z')
        with self.assertRaises(ValueError):ingest.stamp('2026-01-01T00:00:01')

    def test_hash_tampering(self):
        with (self.root/'sysmon.xml').open('a') as f:f.write('tamper')
        with self.assertRaisesRegex(ValueError,'integrity'):ingest.verify_package(self.root)

    def test_manifest_tampering(self):
        (self.root/'manifest.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'digest'):ingest.verify_package(self.root)

    def test_missing_field_and_bad_xml(self):
        p=self.root/'sysmon.xml'
        for raw in ['<Events>', '<Events>'+event(ingest.SOURCES['sysmon'][0],1).replace('<EventRecordID>1</EventRecordID>','')+'</Events>']:
            with self.subTest(raw=raw[:20]):
                p.write_text(raw);seal(self.root)
                self.assertEqual(self.cli(Path(self.temp.name)/'invalid').returncode,1)
                self.assertFalse((Path(self.temp.name)/'invalid').exists())

    def test_wrong_host_channel_id_time_and_count(self):
        p=self.root/'sysmon.xml';original=p.read_text()
        cases=[original.replace('<Computer>TEST-ONLY','<Computer>OTHER'),
               original.replace('<EventID>1','<EventID>999'),
               original.replace('Microsoft-Windows-Sysmon/Operational','Wrong'),
               original.replace('00:00:01.1234567','00:09:01.1234567'),'<Events/>']
        for raw in cases:
            p.write_text(raw);seal(self.root)
            with self.assertRaises(ValueError):ingest.verify_package(self.root)

    def test_duplicate_events_and_dtd(self):
        p=self.root/'sysmon.xml'
        p.write_text('<Events>'+event(ingest.SOURCES['sysmon'][0],1)*2+'</Events>')
        self.meta['channels'][1]['count']=2;self.update_meta()
        with self.assertRaisesRegex(ValueError,'duplicate event'):ingest.verify_package(self.root)
        p.write_text('<!DOCTYPE Events><Events/>');seal(self.root)
        with self.assertRaisesRegex(ValueError,'DTD'):ingest.verify_package(self.root)

    def test_encoding_contract_and_entity_rejection(self):
        p = self.root / 'sysmon.xml'
        xml = '<Events>' + event(ingest.SOURCES['sysmon'][0], 1) + '</Events>'
        for raw in (xml.encode('utf-16'), xml.encode('utf-16-le'),
                    ('<?xml version="1.0" encoding="iso-8859-1"?>' + xml).encode(),
                    ('<!DOCTYPE Events [<!ENTITY x "TEST-ONLY">]>' + xml).encode()):
            p.write_bytes(raw); seal(self.root)
            with self.assertRaises(ValueError): ingest.verify_package(self.root)
        p.write_bytes(('<?xml version="1.0" encoding="utf-8"?>' + xml).encode())
        seal(self.root)
        self.assertEqual(len(ingest.verify_package(self.root)[0]), 2)

    def test_event_coverage_is_explicit_not_fabricated(self):
        rows, summary = ingest.verify_package(self.root)
        self.assertEqual(len(rows), 2)
        self.assertEqual(summary['validated_event_coverage']['security'],
                         dict(observed_event_ids=[4624], unobserved_event_ids=[4625,4672,4688]))
        self.assertEqual(summary['validated_event_coverage']['sysmon'],
                         dict(observed_event_ids=[1], unobserved_event_ids=[3,11,12,13,14]))
        self.assertEqual(summary['required_sources_missing'], [])

    def test_missing_source_partial_and_exit_two(self):
        p=self.root/'sysmon.xml';p.rename(self.root/'sysmon.xml.partial')
        self.meta['channels'][1].update(status='partial',file='sysmon.xml.partial')
        self.meta['required_sources_collected']=False;self.update_meta()
        rows,summary=ingest.verify_package(self.root)
        self.assertEqual(len(rows),1)
        self.assertEqual(summary['required_sources_missing'],['sysmon:partial'])
        out=Path(self.temp.name)/'partial-derived'
        self.assertEqual(self.cli(out).returncode,2)
        self.assertTrue((out/'ingestion.json').exists())

    def test_optional_unavailable(self):
        (self.root/'powershell.xml').unlink()
        self.meta['channels'][2].update(status='unavailable',file=None);self.update_meta()
        self.assertEqual(ingest.verify_package(self.root)[1]['required_sources_missing'],[])

    def test_extra_file_and_path_traversal(self):
        (self.root/'unexpected.txt').write_text('TEST ONLY')
        with self.assertRaisesRegex(ValueError,'unmanifested'):ingest.verify_package(self.root)
        manifest=json.loads((self.root/'manifest.json').read_text());manifest['files'][0]['name']='../escape.xml'
        (self.root/'manifest.json').write_text(json.dumps(manifest))
        (self.root/'manifest.sha256').write_text(ingest.digest(self.root/'manifest.json')+'  manifest.json\n')
        with self.assertRaisesRegex(ValueError,'filename'):ingest.verify_package(self.root)

    def test_determinism_source_preservation_and_output_protection(self):
        before={p.name:p.read_bytes() for p in self.root.iterdir()}
        a,b=Path(self.temp.name)/'a',Path(self.temp.name)/'b'
        self.assertEqual(self.cli(a).returncode,0);self.assertEqual(self.cli(b).returncode,0)
        for name in ('events.jsonl','ingestion.json'):self.assertEqual((a/name).read_bytes(),(b/name).read_bytes())
        self.assertEqual(self.cli(a).returncode,1)
        self.assertEqual(self.cli(self.root/'derived').returncode,1)
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.root.iterdir()})

    def test_false_readiness_and_bad_window(self):
        self.meta['required_sources_collected']=False;self.update_meta()
        with self.assertRaisesRegex(ValueError,'readiness'):ingest.verify_package(self.root)
        self.meta['required_sources_collected']=True
        self.meta['collection_start_utc']='2025-01-01T00:00:00Z';self.update_meta()
        with self.assertRaisesRegex(ValueError,'window'):ingest.verify_package(self.root)



class CollectorTimeFiltering(unittest.TestCase):
    """Source-bound temporal model, not Windows execution or endpoint evidence.

    Models Get-WinEvent's ToString -> DateTime.Parse -> ToUniversalTime path.
    Fixed XPath bounds are taken from the collector template. Native Windows
    Event Log execution must still be verified during authorized recollection.
    """
    def query_bounds(self, start, end, local_offset):
        import re
        from datetime import datetime, timezone, timedelta
        source = SCRIPT.with_name('collect_windows.ps1').read_text()
        if 'StartTime=$StartUtc.UtcDateTime; EndTime=$EndUtc.UtcDateTime' in source:
            local = timezone(timedelta(hours=local_offset))
            def legacy(value):
                utc = datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)
                # DateTime.ToString() drops Kind/offset and fractional seconds.
                wall = utc.replace(tzinfo=None, microsecond=0)
                return ingest.stamp(wall.replace(tzinfo=local).astimezone(timezone.utc).isoformat())
            return legacy(start), legacy(end)
        self.assertIn('-FilterXPath $filter', source)
        self.assertIn('$StartUtc.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffffff\'Z\'",', source)
        self.assertIn('$EndUtc.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffffff\'Z\'",', source)
        self.assertIn('@SystemTime >= \'$queryStart\' and @SystemTime <= \'$queryEnd\'', source)
        self.assertNotIn('StartTime=', source)
        return ingest.stamp(start), ingest.stamp(end)

    def test_utc_plus_two_includes_inside_event_once(self):
        start, end = self.query_bounds('2026-09-23T15:59:20Z', '2026-09-23T15:59:30Z', 2)
        # Artificial timestamp corresponding to 17:59:23 local, not a collected record.
        records = ['2026-09-23T17:59:23+02:00']
        hits = [event for event in records if start <= ingest.stamp(event) <= end]
        self.assertEqual(len(hits), 1)

    def test_inclusive_boundaries_at_100ns_precision(self):
        start, end = self.query_bounds('2026-09-23T15:59:20.1234567Z', '2026-09-23T15:59:30.7654321Z', 2)
        events = ['2026-09-23T17:59:20.1234566+02:00',
                  '2026-09-23T17:59:20.1234567+02:00',
                  '2026-09-23T17:59:20.1234568+02:00',
                  '2026-09-23T17:59:30.7654320+02:00',
                  '2026-09-23T17:59:30.7654321+02:00',
                  '2026-09-23T17:59:30.7654322+02:00']
        self.assertEqual([start <= ingest.stamp(e) <= end for e in events],
                         [False, True, True, True, True, False])

    def test_offset_preservation_and_determinism(self):
        expected = ('2026-09-23T15:59:20.0000000Z', '2026-09-23T15:59:30.0000000Z')
        for endpoint_offset in (0, 1, 2, -5, 5.5):
            for _ in range(2):
                self.assertEqual(self.query_bounds('2026-09-23T17:59:20+02:00',
                                                  '2026-09-23T17:59:30+02:00', endpoint_offset), expected)


if __name__=='__main__':unittest.main()
