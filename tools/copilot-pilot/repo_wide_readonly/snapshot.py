"""Reconstruct inert tracked blobs; never checkout or execute historical code."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def relative(name):
    if not isinstance(name, str) or not name or '\\' in name or '\x00' in name:
        raise ValueError('Invalid snapshot path')
    path = PurePosixPath(name)
    if path.is_absolute() or any(x in ('', '.', '..', '.git') for x in name.split('/')):
        raise ValueError('Snapshot path escape')
    return name


def git(repo, *args):
    result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null',
                             '-c', 'credential.helper=', '-C', str(repo), *args],
                            capture_output=True, timeout=120, check=False)
    if result.returncode:
        raise ValueError('Historical object operation failed')
    return result.stdout


def build(repo, case, destination, max_bytes=536870912):
    """The size limit blocks a case; it never selects or silently drops files."""
    for side in ('base', 'head'):
        value = case[side]
        if not re.fullmatch('[0-9a-f]{40}', value):
            raise ValueError('Full historical SHA required')
        if git(repo, 'rev-parse', '--verify', value + '^{commit}').decode().strip() != value:
            raise ValueError('Historical commit mismatch')
    if git(repo, 'merge-base', '--is-ancestor', case['base'], case['head']):
        raise ValueError('Unexpected merge-base response')
    # Explicit flags avoid configuration-dependent external diff/textconv.
    diff = git(repo, 'diff', '--no-ext-diff', '--no-textconv', '--binary',
               '--no-renames', '--full-index', '--no-color', '--diff-algorithm=myers',
               '--unified=3', '--inter-hunk-context=0', '--src-prefix=a/', '--dst-prefix=b/',
               case['base'], case['head'], '--')
    entries = []
    for record in git(repo, 'ls-tree', '-rz', '--full-tree', case['head']).split(b'\0'):
        if not record:
            continue
        header, raw_name = record.split(b'\t', 1)
        mode, kind, oid = header.decode('ascii').split(' ')
        name = relative(raw_name.decode('utf-8', errors='strict'))
        if kind != 'blob' or mode not in ('100644', '100755', '120000'):
            raise ValueError('Unsupported tree entry; case must not run partially')
        entries.append((name, mode, oid))
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=False)
    total = 0
    receipt = []
    try:
        for name, mode, oid in sorted(entries):
            content = git(repo, 'cat-file', 'blob', oid)
            if hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest() != oid:
                raise ValueError('Historical blob identity mismatch')
            total += len(content)
            if total > max_bytes:
                raise ValueError('Complete tree exceeds safety limit; no partial review')
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(0o444)
            receipt.append({'path': name, 'git_mode': mode, 'blob_oid': oid,
                            'sha256': sha(content), 'bytes': len(content),
                            'line_count': content.count(b'\n') + int(bool(content) and not content.endswith(b'\n')),
                            'symlink_materialized_as_inert_text': mode == '120000'})
        for directory in sorted((p for p in root.rglob('*') if p.is_dir()), reverse=True):
            directory.chmod(0o555)
        root.chmod(0o555)
    except Exception:
        # Preserve partial material as unaccepted evidence; never label it complete.
        raise
    return {'version': 'repo-wide-readonly-v1.0.0', 'case': case,
            'complete': True, 'file_count': len(receipt), 'bytes': total,
            'files': receipt, 'tree_sha': git(repo, 'rev-parse', case['head'] + '^{tree}').decode().strip(),
            'snapshot_sha256': sha(canonical(receipt).encode()),
            'diff_sha256': sha(diff), 'diff_bytes': len(diff)}, diff
