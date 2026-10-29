"""Post-generation audit only; no model, credentials, network or output repair.

This does not replace the frozen host. Original workflow verdicts remain facts.
Only exact, unredacted tool-event strings qualify as corroborating tool evidence.
Redacted/missing telemetry is never reconstructed and contributes no extra paths.
"""
import collections
import json
import re

from repo_wide_readonly.snapshot import canonical, relative, sha
from repo_wide_readonly.live_host import initial_prompt
from repo_wide_readonly.validate import validate

VERSION = 'repo-wide-host-validation-v1.0.1'


def require(condition, label):
    if not condition:
        raise ValueError(label)


def diff_paths(diff):
    """Only textual hunks count, never mere names, binary markers or inventory."""
    text = diff.decode('utf-8', errors='strict')
    result = set()
    require(not text or text.startswith('diff --git '), 'DIFF_FORMAT')
    for section in re.split(r'(?m)^diff --git ', text)[1:]:
        lines = section.splitlines()
        header = re.fullmatch(r'a/([^\t\r\n" ]+) b/([^\t\r\n" ]+)', lines[0])
        require(header is not None, 'UNSUPPORTED_DIFF_PATH_ENCODING')
        old, new = map(relative, header.groups())
        require(old == new, 'UNEXPECTED_RENAME')  # frozen snapshot uses --no-renames
        starts = [i for i, line in enumerate(lines) if line.startswith('@@ ')]
        if not starts:
            continue
        before = lines[:starts[0]]
        require(('--- a/' + old in before or '--- /dev/null' in before)
                and ('+++ b/' + new in before or '+++ /dev/null' in before), 'HUNK_SOURCE_HEADERS')
        for n, start in enumerate(starts):
            match = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@.*', lines[start])
            require(match is not None, 'HUNK_HEADER')
            old_count = int(match[2]) if match[2] is not None else 1
            new_count = int(match[4]) if match[4] is not None else 1
            a = b = 0
            stop = starts[n + 1] if n + 1 < len(starts) else len(lines)
            for line in lines[start + 1:stop]:
                if line == '\\ No newline at end of file':
                    continue
                require(bool(line) and line[0] in ' +-','HUNK_CONTENT')
                a += line[0] in ' -'; b += line[0] in ' +'
            require((a, b) == (old_count, new_count), 'HUNK_INCOMPLETE')
        result.add(new)
    return result


def attest(private_bytes, expected_sha, expected_case, diff, task, schema, expected_session, expected_binding,
           *, prompt_builder=initial_prompt):
    require(sha(private_bytes) == expected_sha, 'IMMUTABLE_PRIVATE_EVIDENCE_HASH')
    d = json.loads(private_bytes)
    r = d['snapshot_receipt']; host = d['host_receipt']; case = r['case']
    require(d['session_id'] == expected_session and d['binding'] == expected_binding
            and host['binding'] == expected_binding, 'SESSION_EXECUTION_BINDING')
    require(case == expected_case and d['base'] == case['base'] and d['head'] == case['head']
            and d['binding']['case'] == case['id'], 'HISTORICAL_IDENTITY')
    require(r['complete'] is True and r['file_count'] == len(r['files']), 'INCOMPLETE_SNAPSHOT')
    require(sha(canonical(r['files']).encode()) == r['snapshot_sha256'] == d['snapshot_sha256'],
            'SNAPSHOT_INVENTORY_HASH')
    files = {relative(x['path']): x for x in r['files']}
    require(len(files) == r['file_count'], 'DUPLICATE_SOURCE')
    require(sha(diff) == r['diff_sha256'] == d['diff_sha256'] and len(diff) == r['diff_bytes'],
            'COMPLETE_DIFF_INTEGRITY')
    prompt = prompt_builder(task, r, diff, schema)
    require(sha(prompt.encode()) == d['prompt_sha256'] == host['prompt_sha256'], 'INITIAL_INPUT_HASH')
    require(d['status'] == host['execution_status'] == 'COMPLETED'
            and d['initial_user_prompts'] == 1 and host['owned_containers_absent'] is True,
            'INCOMPLETE_EXECUTION')
    require(set(d['os_isolation']) and len(d['os_isolation']) == 9
            and all(v is True for v in d['os_isolation'].values()), 'ISOLATION')
    require(sorted(t['name'] for t in d['tool_catalog']['tools'])
            == ['repo_glob', 'repo_grep', 'repo_view'], 'TOOL_CATALOG')
    # Exact strings corroborate returned data. No fuzzy matching or secret recovery.
    event_strings = collections.defaultdict(list)
    for e in d['events']:
        if e['type'] == 'tool.execution_complete' and e['data'].get('success') is True:
            text = e['data'].get('result', {}).get('content')
            if isinstance(text, str):
                event_strings[sha(text.encode())].append(text)
    tools = set(); uncorroborated = 0; corroborated = 0
    for row in d['tool_audit']:
        require(row['tool'] in ('view', 'grep', 'glob'), 'UNSUPPORTED_TOOL')
        if row['ok'] is not True:
            continue
        candidates = event_strings.get(row['response_sha256'], [])
        if not candidates:
            uncorroborated += 1
            continue  # no paths authorized by absent or redacted telemetry
        text = candidates.pop(0); response = row['response']
        require(len(text.encode()) == row['response_bytes'] and json.loads(text) == response,
                'TOOL_RESPONSE_INTEGRITY')
        corroborated += 1
        if row['tool'] == 'view':
            p = relative(response['path']); source = files.get(p)
            require(source is not None and response['commit'] == case['head']
                    and response['side'] == 'head' and row['arguments']['path'] == p
                    and response['blob_oid'] == source['blob_oid']
                    and response['source_sha256'] == source['sha256'], 'TOOL_SOURCE_IDENTITY')
            if response.get('lines') or response.get('content'):
                tools.add(p)
        elif row['tool'] == 'grep':
            for match in response['matches']:
                p = relative(match['path']); source = files.get(p)
                require(source is not None and match['source_sha256'] == source['sha256']
                        and 1 <= match['line'] <= source['line_count'], 'GREP_SOURCE_IDENTITY')
                tools.add(p)
    supplied_diff = diff_paths(diff)
    # Original validator, unmodified output, existing schema, exact historical receipt.
    # Base-side citations without separately verified base data still fail closed.
    value, validation = validate(d['raw_output'], r, tools | supplied_diff, {})
    return {'version': VERSION, 'status': 'PASS', 'case': case,
            'private_evidence_sha256': expected_sha, 'initial_prompt_sha256': d['prompt_sha256'],
            'diff_sha256': sha(diff), 'diff_bytes': len(diff),
            'textual_diff_paths': sorted(supplied_diff), 'corroborated_tool_paths': sorted(tools),
            'exact_tool_events': corroborated, 'uncorroborated_tool_rows_excluded': uncorroborated,
            'diff_only_claims': sorted(set(value['coverage']['inspected_paths']) - tools),
            'validation': validation, 'original_workflow_verdict_replaced': False,
            'model_visible_input_changed': False, 'model_attention_proved': False,
            'live_backend_payload_independently_captured': False,
            'proof_scope': 'Canonical input hashes plus recorded exact tool responses; post-generation channel accounting, not a backend transport capture.'}
