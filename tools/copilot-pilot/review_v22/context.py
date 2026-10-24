"""Deterministic bounded structural/lexical dependency analysis, not a compiler.

Inputs are verified historical text dictionaries, never a working tree. Every
uncertain edge and budget omission is retained. No semantic-completeness claim.
"""
import ast
from collections import defaultdict, deque
import hashlib
import json
from pathlib import PurePosixPath
import re

CONTRACT = 'context-completeness-v1.0.0'
POLICY = dict(max_depth=3, max_units=512, max_edges=4096,
              max_candidates_per_symbol=24, max_block_lines=160,
              max_index_bytes=67108864, max_file_bytes=8388608,
              max_prompt_bytes=262144, max_diff_bytes=196608,
              page_bytes=4000, max_pages=256)
CODE = {'.py', '.swift', '.ts', '.tsx', '.js', '.jsx', '.go', '.rs',
        '.java', '.kt', '.c', '.h', '.cpp', '.cs', '.m', '.mm', '.rb', '.sh'}
CONFIG = {'.json', '.yaml', '.yml', '.toml', '.xml', '.plist', '.ini'}
IDENT = re.compile(r'\b[A-Za-z_][A-Za-z_0-9]*\b')
DECL = re.compile(r'\b(?:(?:async\s+)?(?:func|function|def|fn)\s+|(?:get|set)\s+)([A-Za-z_]\w*)\s*\(')
METHOD = re.compile(r'^\s*(?:(?:public|private|static|async|override|protected|internal|final|mutating)\s+)*([A-Za-z_]\w*)\s*\([^;]*\)\s*(?::[^={]+)?\s*\{')
PROPERTY = re.compile(r'\b(?:var|let|const)\s+([A-Za-z_]\w*)\s*(?::[^={]+)?\s*(?:=|\{)')
TYPE = re.compile(r'\b(?:class|struct|enum|interface|protocol|extension|impl|trait)\s+([A-Za-z_]\w*)')
CALL = re.compile(r'\b([A-Za-z_]\w*)\s*\(')
MEMBER = re.compile(r'\b(?:self|this)\.([A-Za-z_]\w*)')
KEY = re.compile(r'(?:["\x27]([A-Za-z_][A-Za-z_0-9.-]*)["\x27]\s*:|^\s*([A-Za-z_][A-Za-z_0-9.-]*)\s*[:=])', re.M)
IGNORE = {'if', 'for', 'while', 'switch', 'catch', 'return', 'print', 'assert',
          'typeof', 'sizeof', 'super', 'init', 'require', 'import'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_path(path):
    parsed = PurePosixPath(path)
    if (not path or parsed.is_absolute() or '..' in parsed.parts or '\\' in path
            or str(parsed) != path):
        raise ValueError('Noncanonical historical path')
    return path


def mask(text):
    """Offset-preserving strings/comments mask for brace matching only.

    Interpolation/regex/macros are not parsed as language semantics; receipt
    advertises that limitation. Source content itself is never altered.
    """
    pattern = r'"""[\s\S]*?"""|\x27\x27\x27[\s\S]*?\x27\x27\x27|/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27|`(?:\\.|[^`\\])*`'
    return re.sub(pattern, lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), text)


def units(path, text, policy):
    """Atomic declaration bodies plus bounded logical ranges for uncovered text.

    Large bodies are represented by labelled ranges, not silently discarded.
    Their parent extent remains in every range for coverage accounting.
    """
    lines = text.splitlines()
    definitions = []
    suffix = PurePosixPath(path).suffix
    if suffix == '.py':
        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    definitions.append((node.lineno, node.end_lineno, node.name,
                                        'type' if isinstance(node, ast.ClassDef) else 'function'))
        except (SyntaxError, ValueError):
            pass
    else:
        masked = mask(text).splitlines()
        for i, line in enumerate(lines):
            found = DECL.search(line) or METHOD.search(line) or PROPERTY.search(line)
            typ = TYPE.search(line)
            if not found and not typ:
                continue
            found = found or typ
            name = found[1]
            if name in IGNORE:
                continue
            kind = 'type' if typ and typ[1] == name else ('property' if PROPERTY.search(line) else 'function')
            depth, opened, end = 0, False, i
            # Multiline declarations: bounded lookahead to the first body.
            for j in range(i, len(lines)):
                code = masked[j]
                if not opened and j > i + 12:
                    break
                for ch in code:
                    if ch == '{':
                        depth += 1; opened = True
                    elif ch == '}':
                        depth -= 1
                end = j
                if opened and depth <= 0:
                    break
                if not opened and (';' in code or (j == i and '=' in code and '{' not in code)):
                    break
            definitions.append((i + 1, end + 1, name, kind))
    # Containers do not swallow their members. Narrowest containing declaration
    # wins for each line; types contribute header lines, not full-class packets.
    # Local bindings do not replace their containing function as an extraction
    # boundary. Otherwise a changed assignment would deliver one binding while
    # omitting the surrounding guards/recovery in that same function.
    definitions = [d for d in definitions if d[3] != 'property' or not any(
        f[3] == 'function' and f[0] <= d[0] <= f[1] for f in definitions)]
    owners = []
    for n in range(1, len(lines) + 1):
        candidates = [d for d in definitions if d[0] <= n <= d[1]]
        owner = min(candidates, key=lambda d: (d[1]-d[0], d[0], d[2])) if candidates else None
        owners.append(owner)
    result = []
    start = 1
    while start <= len(lines):
        owner = owners[start - 1]
        end = start
        while end < len(lines) and owners[end] == owner and end-start+1 < policy['max_block_lines']:
            end += 1
        name, kind = (owner[2], owner[3]) if owner else ('', 'logical_range')
        result.append(dict(path=path, start=start, end=end, symbol=name, kind=kind,
                           parent_start=owner[0] if owner else start,
                           parent_end=owner[1] if owner else end,
                           partial_parent=bool(owner and (start != owner[0] or end != owner[1])),
                           text='\n'.join(lines[start-1:end])))
        start = end + 1
    return result


def changed_lines(diff):
    """Exact hunk line coordinates on both sides, including deletion-only hunks."""
    rows = {'base': defaultdict(set), 'head': defaultdict(set)}
    old_path = new_path = None
    old = new = 0
    in_hunk = False
    def path(value,prefix):
        if value=='/dev/null':return None
        if value.startswith('"'):
            try:
                value=ast.literal_eval(value)
                try:value=value.encode('latin1').decode('utf-8')
                except (UnicodeEncodeError,UnicodeDecodeError):pass
            except (ValueError,SyntaxError):raise ValueError('Unsupported quoted diff path') from None
        if not isinstance(value,str) or not value.startswith(prefix):
            raise ValueError('Unexpected diff path')
        return safe_path(value[len(prefix):])
    for line in diff.splitlines():
        if line.startswith('diff --git '):
            in_hunk = False
        elif line.startswith('--- '):
            old_path = path(line[4:],'a/')
        elif line.startswith('+++ '):
            new_path = path(line[4:],'b/')
        elif line.startswith('@@ '):
            m = re.match(r'@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@', line)
            if not m:
                raise ValueError('Unsupported hunk coordinates')
            old, new = map(int, m.groups()); in_hunk = True
        elif in_hunk:
            if line.startswith('-'):
                if old_path: rows['base'][old_path].add(old)
                old += 1
            elif line.startswith('+'):
                if new_path: rows['head'][new_path].add(new)
                new += 1
            elif line.startswith(' '):
                old += 1; new += 1
    return rows


def discover(texts, diff, policy=None, side='head'):
    """Uniform reverse/forward symbol, member/state and config-key closure.

    Every edge is a candidate, not an assertion of semantic necessity. No GT,
    PR identity, case IDs, repo names or future revisions are accepted here.
    """
    policy = dict(POLICY if policy is None else policy)
    all_units, omissions = {}, []
    if side not in ('base', 'head'):
        raise ValueError('Historical side required')
    changed = changed_lines(diff)[side]
    total = 0
    for path, text in sorted(texts.items()):
        safe_path(path)
        if PurePosixPath(path).suffix not in CODE | CONFIG | {'.md'}:
            omissions.append(dict(path=path, reason='unsupported_file_type')); continue
        size = len(text.encode()); total += size
        if size > policy['max_file_bytes'] or total > policy['max_index_bytes']:
            # Retain exact changed windows even beyond the indexing ceiling.
            # The containing scope is explicitly unknown, never called complete.
            omissions.append(dict(path=path, reason='index_limit', bytes=size))
            lines=text.splitlines()
            windows=set()
            for number in sorted(changed.get(path,set())):
                start=max(1,number-policy['max_block_lines']//2)
                end=min(len(lines),start+policy['max_block_lines']-1)
                windows.add((start,end))
            for start,end in sorted(windows):
                key=f'{path}:{start}-{end}'
                all_units[key]=dict(path=path,start=start,end=end,symbol='',kind='bounded_unparsed_change',
                                    parent_start=start,parent_end=end,partial_parent=True,
                                    text='\n'.join(lines[start-1:end]))
            continue
        for row in units(path, text, policy):
            key = f'{path}:{row["start"]}-{row["end"]}'
            all_units[key] = row
    definitions, references, properties, keys = (defaultdict(set) for _ in range(4))
    folded_references=defaultdict(set)
    for key, row in all_units.items():
        # Only declaration-start range defines a symbol; remaining ranges are
        # linked explicitly below and not misclassified as duplicate overloads.
        if row['symbol'] and row['start'] == row['parent_start']:
            definitions[row['symbol']].add(key)
        for token in set(IDENT.findall(row['text'])):
            references[token].add(key)
            folded_references[token.casefold()].add(key)
        for token in set(MEMBER.findall(row['text'])) | set(PROPERTY.findall(row['text'])):
            properties[token].add(key)
        for pair in KEY.findall(row['text']):
            token = pair[0] or pair[1]
            keys[token].add(key)
    seeds = sorted(k for k, r in all_units.items()
                   if changed[r['path']].intersection(range(r['start'], r['end']+1)))
    queue = deque((key, 0, 'changed_range', None) for key in seeds)
    selected, edges, seen = [], [], set()
    while queue:
        key, depth, reason, origin = queue.popleft()
        if key in seen:
            continue
        seen.add(key)
        if len(selected) >= policy['max_units']:
            omissions.append(dict(unit=key, reason='unit_limit', depth=depth)); continue
        row = dict(all_units[key], unit=key, depth=depth, reason=reason, origin=origin)
        selected.append(row)
        targets = defaultdict(set)
        parent = (row['path'], row['parent_start'], row['parent_end'], row['symbol'])
        for other, value in all_units.items():
            if (row['kind'] != 'type' and
                    (value['path'], value['parent_start'], value['parent_end'], value['symbol']) == parent and other != key):
                targets['parent_ranges'].add(other)
        calls = set(CALL.findall(mask(row['text']))) - IGNORE
        for token in sorted(calls):
            matches = definitions.get(token, set())
            if not matches:
                # Includes external/runtime calls: explicitly unresolved.
                targets['unresolved_call:' + token] = set()
            elif len(matches) > 1:
                targets['ambiguous_call:' + token] |= matches
            else:
                targets['callee:' + token] |= matches
        if row['symbol']:
            targets['references:' + row['symbol']] |= references[row['symbol']] - {key}
        # Generic data-driven bridge: module/file stems are frequently exported
        # through string keys or enum members across language/runtime boundaries.
        # It is still a lexical candidate edge and retains the same fanout cap.
        if depth == 0:
            stem=PurePosixPath(row['path']).stem
            if re.fullmatch(r'[A-Za-z_]\w{3,}',stem):
                targets['module_key:'+stem.casefold()] |= folded_references[stem.casefold()]
        for token in sorted(set(MEMBER.findall(row['text'])) | set(PROPERTY.findall(row['text']))):
            targets['state:' + token] |= properties[token] | definitions.get(token, set())
        for token in sorted(set(IDENT.findall(row['text'])) & keys.keys()):
            targets['configuration:' + token] |= keys[token]
        for kind, matches in sorted(targets.items()):
            matches = sorted(matches - {key})
            status = ('UNRESOLVED' if kind.startswith('unresolved') else
                      'AMBIGUOUS' if kind.startswith('ambiguous') else 'RESOLVED')
            if len(matches) > policy['max_candidates_per_symbol']:
                status = 'FANOUT_LIMIT'
            elif depth >= policy['max_depth'] and matches:
                status = 'DEPTH_LIMIT'
            # A high-fanout edge retains exact count/digest and an explicit
            # bounded candidate prefix, not megabytes of repeated path lists.
            edge = dict(source=key, kind=kind,
                        target_count=len(matches), targets_sha256=digest(canonical(matches).encode()),
                        targets=matches[:policy['max_candidates_per_symbol']], status=status)
            if len(edges) >= policy['max_edges']:
                omissions.append(dict(unit=key, reason='edge_limit')); break
            edges.append(edge)
            if status not in ('FANOUT_LIMIT', 'DEPTH_LIMIT'):
                queue.extend((target, depth+1, kind, key) for target in matches)
    return dict(contract=CONTRACT, policy=policy, selected=selected, dependencies=edges,
                omissions=omissions, seed_units=seeds,
                semantic_completeness=False,
                limitations=['Structural/lexical candidates are not a sound interprocedural call graph.',
                             'Dynamic dispatch, macros, external APIs and cross-language bridges need independent audit.',
                             'Large declarations are labelled partial ranges until every parent range is delivered.'])
