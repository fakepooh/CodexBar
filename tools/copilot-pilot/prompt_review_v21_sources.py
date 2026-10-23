"""OFFLINE ONLY: deterministic, historical-only navigation supplement for v2.

No credential, process, network, budget or live execution entry point. Lexical
links are candidates, not a call graph or proof of semantic coverage.
"""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re

import pilot as p

TRACK = 'copilot_cli_prompt_review_v2'
TEMPLATE = Path(__file__).resolve().parent / 'prompt-review-v2/review-prompt.txt'
POLICY = {'hops': 2, 'max_files': 32, 'max_bytes': 131072,
          'max_symbol_document_frequency': 48, 'page_bytes': 8000,
          'max_source_bytes': 1048576}
SOURCE_EXTENSIONS = {'.md', '.sh', '.zsh', '.bash', '.yml', '.yaml', '.json', '.toml', '.xml', '.plist', '.swift', '.ts', '.tsx', '.js', '.jsx', '.py', '.go', '.rs',
                     '.java', '.kt', '.c', '.h', '.cpp', '.cs', '.m', '.mm', '.rb'}
TOKEN = re.compile(r'\b[A-Za-z_][A-Za-z_0-9]{3,}\b')
DECLARATION = re.compile(r'\b(?:class|struct|enum|interface|protocol|type|func|function|def)\s+([A-Za-z_][A-Za-z_0-9]{3,})')


def historical_sources(context, case):
    """Verify every blob's Git identity; derive candidates only from inert trees."""
    context = Path(context)
    meta = p.check_context(context, case)
    index = p.load(context / 'index.json')
    if index.get('base') != case['base'] or index.get('head') != case['head']:
        raise ValueError('Historical index SHA mismatch')
    decoded = {}
    for rows in index['trees'].values():
        for row in rows:
            if row['type'] != 'blob' or row['oid'] in decoded:
                continue
            import base64
            value = p.load(context / 'blobs' / (row['oid'] + '.json'))
            if value['encoding'] not in ('utf-8', 'base64'):
                raise ValueError('Unsupported historical encoding')
            raw = (value['content'].encode() if value['encoding'] == 'utf-8'
                   else base64.b64decode(value['content'], validate=True))
            oid = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            if value['git_oid'] != row['oid'] or oid != row['oid']:
                raise ValueError('Historical blob identity mismatch')
            decoded[oid] = value
    trees = {side: {row['path']: row for row in rows if row['type'] == 'blob'}
             for side, rows in index['trees'].items()}
    texts = {}
    for path, row in sorted(trees['head'].items()):
        value = decoded[row['oid']]
        # Symlinks remain inert and are never considered source dependencies.
        if (row['mode'] in ('100644', '100755') and Path(path).suffix in SOURCE_EXTENSIONS
                and value['encoding'] == 'utf-8'
                and len(value['content'].encode()) <= POLICY['max_source_bytes']):
            texts[path] = value['content']
    changed = sorted(path for path in set(trees['base']) | set(trees['head'])
                     if trees['base'].get(path) != trees['head'].get(path))
    return meta, trees, texts, changed


def select(texts, changed, policy=None):
    """Two-hop reverse references to declarations and file stems, fixed budgets.

    No timeout words, provider names, case IDs or expected finding inputs. A
    document-frequency cap avoids universal symbols dominating the packet.
    """
    policy = dict(POLICY if policy is None else policy)
    tokens = {path: set(TOKEN.findall(text)) for path, text in sorted(texts.items())}
    references = defaultdict(set)
    definitions = defaultdict(set)
    for path, values in tokens.items():
        for token in sorted(values):
            references[token].add(path)
        for symbol in DECLARATION.findall(texts[path]):
            definitions[symbol].add(path)
    selected, omissions = [], []
    seen, used = set(), 0
    frontier = sorted(set(changed) & set(texts))
    for hop in range(policy['hops'] + 1):
        next_frontier = set()
        for path in frontier:
            if path in seen:
                continue
            seen.add(path)
            size = len(texts[path].encode())
            if len(selected) >= policy['max_files'] or used + size > policy['max_bytes']:
                omissions.append({'path': path, 'hop': hop, 'reason': 'packet budget'})
                continue
            used += size
            selected.append({'path': path, 'hop': hop, 'bytes': size})
            symbols = set(DECLARATION.findall(texts[path]))
            stem = Path(path).stem
            if TOKEN.fullmatch(stem):
                symbols.add(stem)
            for symbol in sorted(symbols):
                paths = references.get(symbol, set())
                if len(paths) <= policy['max_symbol_document_frequency']:
                    next_frontier.update(paths)
        frontier = sorted(next_frontier - seen)
    # Preserve the established reverse-reference priority. Only remaining
    # budget is used for forward declared interfaces/configuration/dependencies;
    # otherwise common forward names can displace the unchanged callers.
    for hop in range(1, policy['hops'] + 1):
        candidates = set()
        for row in list(selected):
            if row['hop'] != hop - 1:
                continue
            for symbol in sorted(tokens[row['path']] & definitions.keys()):
                if len(references[symbol]) <= policy['max_symbol_document_frequency']:
                    candidates.update(definitions[symbol])
        for path in sorted(candidates - seen):
            seen.add(path); size = len(texts[path].encode())
            if len(selected) >= policy['max_files'] or used + size > policy['max_bytes']:
                omissions.append({'path': path, 'hop': hop, 'reason': 'packet budget'})
                continue
            used += size
            selected.append({'path': path, 'hop': hop, 'bytes': size})
    return {'policy': policy, 'selected': selected, 'omissions': omissions,
            'source_bytes': used,
            'limitations': ['Lexical references are not a complete call graph.',
                'Only bounded UTF-8 head source is selected; full base/head remain in the sealed snapshot.',
                'References beyond the hop, frequency, size and packet bounds are not guaranteed.',
                'Packet existence does not prove model delivery or inspection.']}


def pages(text, max_bytes):
    """JSONL records preserve source line numbers, even for long source lines."""
    if max_bytes <= 100:
        raise ValueError('Page bound too small for a source record')
    fragment_chars = min(500, (max_bytes - 100) // 12)
    page, size = [], 0
    for number, line in enumerate(text.splitlines(), 1):
        # Bound escaped output size by slicing source strings before encoding.
        fragments = [line[i:i + fragment_chars] for i in range(0, len(line), fragment_chars)] or ['']
        for part, fragment in enumerate(fragments):
            record = json.dumps({'line': number, 'part': part, 'text': fragment}, ensure_ascii=True) + '\n'
            if page and size + len(record.encode()) > max_bytes:
                yield ''.join(page)
                page, size = [], 0
            if len(record.encode()) > max_bytes:
                raise ValueError('Page bound cannot encode a source fragment')
            page.append(record)
            size += len(record.encode())
    if page:
        yield ''.join(page)


def navigation(records):
    """Small index pages, independently bounded from source pages."""
    chunks, current, size = [], [], 0
    for record in records:
        for page in record['pages']:
            line = json.dumps({'path': record['path'], 'oid': record['oid'],
                               'hop': record['hop'], 'source_page': page}) + '\n'
            if len(line.encode()) > POLICY['page_bytes'] - 200:
                raise ValueError('Historical path too long for bounded navigation')
            if size + len(line.encode()) > POLICY['page_bytes'] - 200:
                chunks.append(''.join(current)); current, size = [], 0
            current.append(line); size += len(line.encode())
    chunks.append(''.join(current))
    return {f'navigation-{i:04d}.jsonl': text + json.dumps({'next':
            f'navigation-{i+1:04d}.jsonl' if i+1 < len(chunks) else None}) + '\n'
            for i, text in enumerate(chunks)}


def dry_run(context, case, output):
    """Write a supplement and a plan, never mount or execute it.

    A future adapter must seal this with the historical snapshot and revalidate
    the read-only mount/allowlist. Existing live runners cannot consume v2.
    """
    output = Path(output)
    if output.exists():
        raise ValueError('Preserve existing evidence; output must be new')
    meta, trees, texts, changed = historical_sources(context, case)
    selection = select(texts, changed)
    output.mkdir(parents=True, mode=0o700)
    records = []
    for selected in selection['selected']:
        path = selected['path']
        oid = trees['head'][path]['oid']
        names = []
        for part, content in enumerate(pages(texts[path], POLICY['page_bytes'])):
            name = f'{oid}-{part:04d}.jsonl'
            (output / name).write_text(content)
            names.append(name)
        records.append({**selected, 'side': 'head', 'oid': oid, 'pages': names})
    for name, content in navigation(records).items():
        (output / name).write_text(content)
    plan = {'schema_version': 1, 'track': TRACK, 'status': 'offline_dry_run',
            'case': case, 'historical_context_sha256': meta['context_sha256'],
            'prompt_template_sha256': p.digest(TEMPLATE.read_bytes()),
            'selection': selection, 'records': records,
            'files': {x.name: p.digest(x.read_bytes()) for x in sorted(output.iterdir())},
            'ai_requests': 0, 'live_enabled': False, 'authorization_used': False,
            'integration_blocker': 'No v2 live adapter: seal supplement into a single read-only snapshot, validate output allowlist and mandatory delivery before any separately authorized use.'}
    p.save(output / 'plan.json', plan)
    for file in output.iterdir():
        file.chmod(0o444)
    return plan


def verify_packet(context, case, output):
    """Recompute all selection decisions and emitted bytes from historical input."""
    output = Path(output)
    meta, trees, texts, changed = historical_sources(context, case)
    plan = p.load(output / 'plan.json')
    if (plan.get('track') != TRACK or plan.get('case') != case
            or plan.get('historical_context_sha256') != meta['context_sha256']
            or plan.get('prompt_template_sha256') != p.digest(TEMPLATE.read_bytes())
            or plan.get('selection') != select(texts, changed)
            or plan.get('live_enabled') is not False or plan.get('authorization_used') is not False):
        raise ValueError('V2 packet protocol mismatch')
    expected = {}
    records = []
    for selected in plan['selection']['selected']:
        path = selected['path']; oid = trees['head'][path]['oid']
        names = []
        for part, content in enumerate(pages(texts[path], POLICY['page_bytes'])):
            name = f'{oid}-{part:04d}.jsonl'
            names.append(name); expected[name] = content.encode()
        records.append({**selected, 'side': 'head', 'oid': oid, 'pages': names})
    expected.update({name:text.encode() for name,text in navigation(records).items()})
    if plan.get('records') != records or plan.get('files') != {k:p.digest(v) for k,v in sorted(expected.items())}:
        raise ValueError('V2 packet provenance mismatch')
    if ({x.name for x in output.iterdir()} != set(expected) | {'plan.json'}
            or any(x.is_symlink() or not x.is_file() for x in output.iterdir())
            or any((output / name).read_bytes() != raw for name, raw in expected.items())):
        raise ValueError('V2 packet differs from historical source')
    return {'historical_only': True, 'selection_recomputed': True,
            'selected_files': len(records), 'pages': len(expected), 'ai_requests': 0}


def provenance(args, events, usage):
    """Extract only model-selection metadata, never environment or raw settings.

    Omitted --model and a config label alone never attest Auto. A resolution
    event attests this routing decision; it cannot promise future selection.
    """
    explicit = []
    for pos, value in enumerate(args):
        if value.startswith('--model='):
            explicit.append(value.split('=', 1)[1])
        elif value == '--model' and pos + 1 < len(args):
            explicit.append(args[pos + 1])
    if len(explicit) > 1:
        raise ValueError('Ambiguous requested model')
    auto = [x['data'] for x in events if x.get('type') == 'session.auto_mode_resolved']
    actual = sorted(k for k, v in usage.get('modelMetrics', {}).items()
                    if v.get('requests', {}).get('count', 0) > 0)
    if auto and any(x.get('chosenModel') not in actual for x in auto):
        raise ValueError('Routing event and observed usage disagree')
    if auto and explicit and explicit[0] != 'auto':
        raise ValueError('Explicit fixed model conflicts with Auto evidence')
    allowed = ('chosenModel', 'candidateModels', 'availableModels', 'routingMethod', 'fallback', 'categoryScores')
    return {'explicit_argument': explicit[0] if explicit else None,
            'actual_models': actual,
            'mechanism': 'AUTO' if auto else ('EXPLICIT' if explicit else 'UNKNOWN'),
            'auto_events': [{k: value[k] for k in allowed if k in value} for value in auto],
            'effective_settings_captured': False,
            'note': 'Use an allowlisted pre-start settings/env receipt in any future adapter; never dump raw config or environment.'}


def model_inputs(args, environment, settings):
    """Allowlisted pre-start receipt for future integration; no raw env/config.

    Caller supplies the effective CHILD environment and effective settings, not
    the host environment. This helper neither reads nor changes either source.
    """
    def model(value):
        if value is None:
            return None
        if (not isinstance(value, str) or len(value) > 100
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]*', value)
                or re.search(r'(?:github_pat_|gh[pousr]_|sk-)', value)):
            raise ValueError('Unsafe model metadata; no raw value recorded')
        return value
    request = provenance(args, [], {})['explicit_argument']
    return {'cli_model': model(request), 'environment_model': model(environment.get('COPILOT_MODEL')),
            'settings_model': model(settings.get('model')),
            'settings_effort': model(settings.get('effortLevel')),
            'home_is_expected': environment.get('COPILOT_HOME') == '/home/copilot/.copilot',
            'settings_capture_scope': 'model and effort only; tokens and other fields excluded'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', required=True, type=Path)
    parser.add_argument('--case', choices=['CP-02'], required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    case = next(c for c in p.cases() if c['id'] == args.case)
    result = dry_run(args.context, case, args.out)
    print(json.dumps({'status': result['status'], 'ai_requests': 0,
                      'selected_files': len(result['records']), 'live_enabled': False}))
