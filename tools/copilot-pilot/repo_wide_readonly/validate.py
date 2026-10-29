"""Offline strict output validation; no model, credentials or evaluator data.

A single conventional JSON code fence may be removed as framing. No partial JSON,
repairs, semantic rewriting, external schema resolution or follow-up turns.
"""
import json
from pathlib import Path
import re

from .snapshot import relative, canonical, sha


def pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValueError('DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def check(value, rule):
    allowed = {'$schema', 'title', 'type', 'additionalProperties', 'required', 'properties',
               'items', 'const', 'enum', 'pattern', 'minimum', 'minLength', 'minItems', 'uniqueItems'}
    if set(rule) - allowed:
        raise ValueError('UNSUPPORTED_SCHEMA_RULE')
    if 'const' in rule and canonical(value) != canonical(rule['const']):
        raise ValueError('OUTPUT_CONST')
    if 'enum' in rule and not any(canonical(value) == canonical(v) for v in rule['enum']):
        raise ValueError('OUTPUT_ENUM')
    kind = rule.get('type')
    types = {'object': dict, 'array': list, 'string': str, 'integer': int}
    if kind and (kind not in types or type(value) is not types[kind]):
        raise ValueError('OUTPUT_TYPE')
    if kind == 'object':
        properties = rule.get('properties', {})
        if set(rule.get('required', [])) - set(value):
            raise ValueError('OUTPUT_REQUIRED')
        if rule.get('additionalProperties') is False and set(value) - set(properties):
            raise ValueError('OUTPUT_EXTRA_FIELD')
        for key, item in value.items():
            if key in properties:
                check(item, properties[key])
    if kind == 'array':
        if len(value) < rule.get('minItems', 0):
            raise ValueError('OUTPUT_MIN_ITEMS')
        if rule.get('uniqueItems') and len({canonical(v) for v in value}) != len(value):
            raise ValueError('OUTPUT_DUPLICATES')
        for item in value:
            check(item, rule['items'])
    if kind == 'string':
        if len(value) < rule.get('minLength', 0):
            raise ValueError('OUTPUT_MIN_LENGTH')
        if 'pattern' in rule and not re.search(rule['pattern'], value):
            raise ValueError('OUTPUT_PATTERN')
    if kind == 'integer' and value < rule.get('minimum', value):
        raise ValueError('OUTPUT_MINIMUM')


def validate(raw, receipt, delivered_paths, base_files=None):
    if not isinstance(raw, str) or len(raw.encode()) > 2097152:
        raise ValueError('OUTPUT_SIZE_OR_ENCODING')
    text = raw.strip(); fenced = False
    for prefix in ('```json\n', '```\n'):
        if text.startswith(prefix) and text.endswith('\n```'):
            text = text[len(prefix):-4]; fenced = True; break
    try:
        value = json.loads(text, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))
    except (json.JSONDecodeError, RecursionError):
        raise ValueError('OUTPUT_NOT_SINGLE_JSON') from None
    schema = json.loads((Path(__file__).parent / 'output.schema.json').read_text())
    check(value, schema)
    case = receipt['case']
    if receipt.get('complete') is not True or value['base_sha'] != case['base'] or value['head_sha'] != case['head']:
        raise ValueError('OUTPUT_HISTORICAL_IDENTITY')
    head_files = {row['path']: row for row in receipt['files']}
    if len(head_files) != receipt['file_count']:
        raise ValueError('OUTPUT_INVALID_SNAPSHOT_RECEIPT')
    delivered = set(delivered_paths)
    for path in value['coverage']['inspected_paths']:
        relative(path)
        if path not in delivered:
            raise ValueError('OUTPUT_UNSUPPORTED_CONTEXT_CLAIM')
    identifiers = set()
    for finding in value['findings']:
        relative(finding['path'])
        if finding['id'] in identifiers:
            raise ValueError('OUTPUT_DUPLICATE_FINDING_ID')
        identifiers.add(finding['id'])
        files = head_files if finding['side'] == 'head' else (base_files or {})
        source = files.get(finding['path'])
        if not source or not (1 <= finding['line_start'] <= finding['line_end'] <= source['line_count']):
            raise ValueError('OUTPUT_UNVERIFIED_SOURCE_RANGE')
    return value, {'status': 'PASS', 'raw_sha256': sha(raw.encode()),
                   'parsed_sha256': sha(canonical(value).encode()), 'json_framing_removed': fenced,
                   'finding_count': len(value['findings']),
                   'claimed_inspected_path_count': len(value['coverage']['inspected_paths']),
                   'semantic_correctness_proved': False, 'model_consumption_proved': False}
