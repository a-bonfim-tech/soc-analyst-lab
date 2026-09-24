"""Verify a private Windows collection and normalize actual Event XML; no enrichment."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

NS = '{http://schemas.microsoft.com/win/2004/08/events/event}'
SOURCES = {
    'security': ('Security', {4624, 4625, 4672, 4688}, True),
    'sysmon': ('Microsoft-Windows-Sysmon/Operational', {1, 3, 11, 12, 13, 14}, True),
    'powershell': ('Microsoft-Windows-PowerShell/Operational', {4103, 4104}, False),
    'defender': ('Microsoft-Windows-Windows Defender/Operational', {1116, 1117}, False),
}


def stamp(value):
    if not isinstance(value, str) or not re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})', value):
        raise ValueError('timezone-aware ISO timestamp required')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    # Windows timestamps have 100 ns precision; retain the seventh digit explicitly.
    fraction = re.search(r'\.(\d+)', value)
    ticks = (fraction.group(1) if fraction else '').ljust(7, '0')
    normalized = parsed.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + '.' + ticks + 'Z'
    return normalized


def load_json(path):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError('duplicate JSON key')
            result[k] = v
        return result
    return json.loads(path.read_text(encoding='utf-8-sig'), object_pairs_hook=unique)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_package(directory):
    if not directory.is_dir():
        raise ValueError('input must be a collection directory')
    if any(p.is_symlink() or not p.is_file() for p in directory.iterdir()):
        raise ValueError('collection must contain regular files only, no symlinks/subdirectories')
    expected = (directory / 'manifest.sha256').read_text().strip()
    if expected != digest(directory / 'manifest.json') + '  manifest.json':
        raise ValueError('manifest digest mismatch')
    manifest = load_json(directory / 'manifest.json')
    if manifest.get('schema_version') != 1 or not isinstance(manifest.get('files'), list):
        raise ValueError('unsupported manifest schema')
    names = set()
    for item in manifest['files']:
        name = item['name']
        allowed = {'metadata.json'} | {n + suffix for n in SOURCES for suffix in ('.xml', '.xml.partial')}
        if name not in allowed or name in names:
            raise ValueError('unexpected or duplicate manifest filename')
        names.add(name)
        path = directory / name
        if path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
            raise ValueError('evidence integrity mismatch: ' + name)
    if names | {'manifest.json', 'manifest.sha256'} != {p.name for p in directory.iterdir()}:
        raise ValueError('unmanifested or missing file')
    if 'metadata.json' not in names:
        raise ValueError('metadata not covered by manifest')
    metadata = load_json(directory / 'metadata.json')
    for key in ('hostname', 'collector', 'os_version', 'powershell_version', 'local_timezone',
                'collection_start_utc', 'collection_end_utc', 'requested_start_utc',
                'requested_end_utc', 'collector_script_sha256'):
        if not isinstance(metadata.get(key), str) or not metadata[key]:
            raise ValueError('missing metadata: ' + key)
    if (metadata.get('schema_version') != 1 or metadata.get('case_id') != 'SOC-2026-003'
            or metadata.get('source_kind') != 'Windows EventRecord.ToXml'
            or metadata.get('authorized_disposable_lab') is not True
            or metadata.get('phase') not in ('baseline', 'final')):
        raise ValueError('invalid collection provenance declarations')
    if not re.fullmatch('[0-9a-f]{64}', metadata['collector_script_sha256']):
        raise ValueError('invalid collector script digest')
    start, end = stamp(metadata['requested_start_utc']), stamp(metadata['requested_end_utc'])
    collected_start, collected_end = stamp(metadata['collection_start_utc']), stamp(metadata['collection_end_utc'])
    if not start < end <= collected_start <= collected_end:
        raise ValueError('invalid collection window ordering')
    if not isinstance(metadata.get('channels'), list):
        raise ValueError('missing channel inventory')
    rows, seen_channels, seen_records, used_files, missing = [], set(), set(), {'metadata.json'}, []
    for channel in metadata['channels']:
        name = channel['name']
        if name not in SOURCES or name in seen_channels:
            raise ValueError('unknown/duplicate channel')
        seen_channels.add(name)
        log, ids, required = SOURCES[name]
        if channel.get('channel') != log or channel.get('required') is not required or set(channel.get('event_ids', [])) != ids:
            raise ValueError('channel contract mismatch')
        status, filename, count = channel['status'], channel['file'], channel['count']
        if type(count) is not int or count < 0:
            raise ValueError('invalid event count')
        if status not in ('collected', 'no_events', 'unavailable', 'partial'):
            raise ValueError('unknown collection status')
        if required and status != 'collected':
            missing.append(name + ':' + status)
        if status in ('unavailable', 'partial'):
            if (status == 'unavailable' and (filename is not None or count != 0)) or (status == 'partial' and filename != name + '.xml.partial'):
                raise ValueError('inconsistent unavailable/partial export')
            if filename:
                if filename not in names:
                    raise ValueError('partial file missing')
                used_files.add(filename)
            continue
        if filename != name + '.xml' or filename not in names:
            raise ValueError('channel export missing')
        used_files.add(filename)
        raw = (directory / filename).read_bytes()
        # Collector exports UTF-8 only. Decode before checking declarations so
        # UTF-16/32 cannot bypass the DTD guard through interleaved NUL bytes.
        text = raw.decode('utf-8-sig')
        declaration = re.search(r"<\?xml\b[^?]*\bencoding\s*=\s*['\"]([^'\"]+)['\"]", text)
        if '\x00' in text or (declaration and declaration.group(1).lower() != 'utf-8'):
            raise ValueError('collector XML must be UTF-8')
        if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
            raise ValueError('DTD/entities prohibited')
        source_hash = hashlib.sha256(raw).hexdigest()
        root = ET.fromstring(text)
        if root.tag != 'Events':
            raise ValueError('expected Events XML wrapper')
        if len(root) != count or (status == 'collected') != (count > 0):
            raise ValueError('event count/status mismatch')
        for index, event in enumerate(root):
            if event.tag != NS + 'Event':
                raise ValueError('expected native Event namespace')
            system = event.find(NS + 'System')
            if system is None:
                raise ValueError('missing System')
            def field(tag):
                element = system.find(NS + tag)
                if element is None or not element.text:
                    raise ValueError('missing event field: ' + tag)
                return element.text
            provider, time = system.find(NS + 'Provider'), system.find(NS + 'TimeCreated')
            if provider is None or not provider.get('Name') or time is None:
                raise ValueError('missing provider/time')
            original_time = time.get('SystemTime')
            utc = stamp(original_time)
            eid, rid, host, event_channel = field('EventID'), field('EventRecordID'), field('Computer'), field('Channel')
            if not eid.isdecimal() or not rid.isdecimal() or int(eid) not in ids or event_channel != log:
                raise ValueError('event outside channel/id contract')
            if host.split('.')[0].casefold() != metadata['hostname'].casefold() or not start <= utc <= end:
                raise ValueError('event outside host/time contract')
            identity = (host.casefold(), log, rid)
            if identity in seen_records:
                raise ValueError('duplicate event identity')
            seen_records.add(identity)
            data = event.find(NS + 'EventData')
            # Preserve duplicate/unnamed Data entries and absent vs empty text.
            event_data = None if data is None else [dict(name=d.get('Name'), value=d.text) for d in data]
            user_data = event.find(NS + 'UserData')
            rows.append(dict(timestamp_original=original_time, timestamp_utc=utc,
                             computer=host, channel=log, provider=provider.get('Name'),
                             event_id=int(eid), record_id=rid, event_data=event_data,
                             user_data_xml=None if user_data is None else ET.tostring(user_data, encoding='unicode'),
                             source_file=filename, source_event_index=index,
                             source_sha256=source_hash))
    if seen_channels != set(SOURCES) or used_files != names:
        raise ValueError('inventory does not account for every source/file')
    if metadata.get('required_sources_collected') is not (not missing):
        raise ValueError('required source readiness mismatch')
    rows.sort(key=lambda r: (r['timestamp_utc'], r['channel'], int(r['record_id'])))
    coverage = {}
    for name, (log, ids, _) in SOURCES.items():
        observed = {row['event_id'] for row in rows if row['channel'] == log}
        coverage[name] = dict(observed_event_ids=sorted(observed),
                              unobserved_event_ids=sorted(ids - observed))
    summary = dict(case_id='SOC-2026-003', phase=metadata['phase'], event_count=len(rows),
                   required_sources_missing=missing, channels=metadata['channels'],
                   validated_event_coverage=coverage,
                   manifest_sha256=digest(directory / 'manifest.json'),
                   note='Integrity and schema verified; provenance authenticity requires operator review. No incident conclusions.')
    return rows, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        source, output = args.input.resolve(), args.output.resolve()
        if output == source or source in output.parents:
            raise ValueError('derived output must be outside the source package')
        if output.exists():
            raise ValueError('output already exists; refusing overwrite')
        rows, summary = verify_package(source)
        # Validate everything before creating any output. Exclusive directory creation.
        output.mkdir()
        with (output / 'events.jsonl').open('x', encoding='utf-8', newline='\n') as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + '\n')
        (output / 'ingestion.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
        print(f'Normalized {len(rows)} source events; missing required sources: {summary["required_sources_missing"]}')
        return 2 if summary['required_sources_missing'] else 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ET.ParseError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
