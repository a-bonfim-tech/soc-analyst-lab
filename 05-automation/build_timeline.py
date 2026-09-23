"""Normalize synthetic evidence. No commands from telemetry are executed."""
import argparse
import csv
import json
import os
from pathlib import Path
import sys
import tempfile
from datetime import datetime, timezone

COLUMNS = ['timestamp', 'source', 'event_id', 'host', 'user', 'activity',
           'evidence', 'attack_technique', 'analyst_note', 'record_id',
           'process_guid', 'logon_id', 'related_records']
SEC_REQUIRED = {'RecordId', 'TimeGenerated', 'Computer', 'EventID', 'Account',
                'LogonType', 'IpAddress', 'TargetLogonId', 'SubjectLogonId',
                'SubjectUserName', 'TargetUserName', 'ProcessName', 'PrivilegeList'}
SYS_REQUIRED = {'RecordId', 'UtcTime', 'Computer', 'EventID', 'Image', 'ParentImage',
                'CommandLine', 'User', 'LogonId', 'ProcessGuid', 'DestinationIp',
                'DestinationPort', 'TargetObject', 'Details', 'EventType'}


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('timestamp must include a timezone')
    return parsed.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def read_evidence(security, sysmon):
    with Path(security).open(encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        if not SEC_REQUIRED.issubset(reader.fieldnames or []):
            raise ValueError('missing Security CSV columns')
        sec = list(reader)
    with Path(sysmon).open(encoding='utf-8') as f:
        sysm = json.load(f)
    if not isinstance(sysm, list):
        raise ValueError('Sysmon JSON must be an array')
    for rows, required in ((sec, SEC_REQUIRED), (sysm, SYS_REQUIRED)):
        ids = set()
        if not rows:
            raise ValueError('empty evidence dataset')
        for row in rows:
            if not isinstance(row, dict) or not required.issubset(row):
                raise ValueError('missing event fields')
            if any(row[k] is None for k in required) or None in row:
                raise ValueError('malformed event fields')
            if not row['RecordId'] or row['RecordId'] in ids:
                raise ValueError('missing or duplicate RecordId')
            ids.add(row['RecordId'])
            if not row['Computer']:
                raise ValueError('missing Computer')
            if any(not isinstance(row[k], str) for k in required - {'EventID', 'DestinationPort'}):
                raise ValueError('event string field has wrong type')
            int(row['EventID'])
            timestamp(row.get('TimeGenerated', row.get('UtcTime')))
    return sec, sysm


def build(security, sysmon):
    sec, sysm = read_evidence(security, sysmon)
    result = []
    for source, events in [('Security', sec), ('Sysmon', sysm)]:
        for event in events:
            eid = int(event['EventID'])
            row = dict.fromkeys(COLUMNS, '')
            row.update(timestamp=timestamp(event.get('TimeGenerated', event.get('UtcTime'))),
                       source=source, event_id=str(eid), host=event['Computer'],
                       user=event.get('Account', event.get('User', '')),
                       record_id=event['RecordId'], process_guid=event.get('ProcessGuid', ''),
                       logon_id=(event.get('TargetLogonId') or event.get('SubjectLogonId')
                                 or event.get('LogonId', '')),
                       evidence=json.dumps(event, sort_keys=True, separators=(',', ':')),
                       analyst_note='Synthetic observation; no automated maliciousness conclusion.')
            row['activity'] = ({4624:'Successful logon',4625:'Failed logon',4672:'Special privileges assigned'}
                               if source == 'Security' else
                               {1:'Process creation',3:'Network connection',13:'Registry value set'}).get(eid, 'Unclassified event')
            # ATT&CK is deliberately left empty: mapping requires analyst interpretation.
            result.append(row)
    result.sort(key=lambda row: (row['timestamp'], row['source'], row['record_id']))
    for row in result:
        # Correlate exact host+process or host+nonempty session; no temporal causality inferred.
        related = [other['source'] + ':' + other['record_id'] for other in result
                   if other is not row and other['host'] == row['host'] and
                   ((row['process_guid'] and row['process_guid'] == other['process_guid']) or
                    (row['logon_id'] and row['logon_id'] == other['logon_id']))]
        row['related_records'] = ';'.join(related)
    return result


def write_timeline(rows, output):
    output = Path(output)
    # Atomic replacement only after all input validation; no partial report on errors.
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='',
                                         dir=output.parent, delete=False) as f:
            tmp = Path(f.name)
            writer = csv.DictWriter(f, fieldnames=COLUMNS, lineterminator='\n')
            writer.writeheader()
            writer.writerows(rows)
        os.replace(tmp, output)
    finally:
        if tmp is not None and tmp.exists():
            tmp.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--security-events', type=Path, required=True)
    parser.add_argument('--sysmon', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.output.resolve() in {args.security_events.resolve(), args.sysmon.resolve()}:
            raise ValueError('output must not overwrite source evidence')
        rows = build(args.security_events, args.sysmon)
        write_timeline(rows, args.output)
        print(f'Wrote {len(rows)} synthetic timeline records')
    except (OSError, ValueError, TypeError, KeyError, csv.Error) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
