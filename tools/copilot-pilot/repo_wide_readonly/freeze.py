"""Explicit deterministic preregistration; never generates reviewer/evaluator facts."""
import argparse
import json
import os
from pathlib import Path
from .snapshot import canonical, sha

DRAFT = {'methodology': 'repo-wide-readonly-v1.0.0', 'status': 'NOT_FROZEN'}


def sources(root):
    root = Path(root)
    return sorted(p for p in root.rglob('*') if p.is_file()
                  and 'node_modules' not in p.parts and '__pycache__' not in p.parts
                  and p.name not in {'freeze.json', 'README.md'}
                  and (p.suffix in {'.py', '.mjs', '.json'} or p.name in {'Dockerfile', '.dockerignore'}))


def inventory(root):
    root = Path(root)
    return {str(p.relative_to(root)): sha(p.read_bytes()) for p in sources(root)}


def workflows(root):
    repo = Path(root).parents[2]
    return {name: sha((repo / '.github/workflows' / name).read_bytes())
            for name in ['ci.yml', 'copilot-repo-wide-live.yml']}


def verify(root):
    root = Path(root)
    value = json.loads((root / 'freeze.json').read_text())
    if (value.get('methodology') != 'repo-wide-readonly-v1.0.0' or value.get('status') != 'FROZEN'
            or value.get('files') != inventory(root) or value.get('workflows') != workflows(root)):
        raise ValueError('FROZEN_IMPLEMENTATION_MISMATCH')
    method = json.loads((root / 'methodology.json').read_text())
    if (method.get('status') != 'FROZEN' or method.get('unknown_allowance_exception') is not True
            or method.get('live_enabled') is not True):
        raise ValueError('UNFROZEN_OR_UNAUTHORIZED_METHOD')
    return {'freeze_sha256': sha((root / 'freeze.json').read_bytes()),
            'methodology_sha256': sha((root / 'methodology.json').read_bytes()), 'files': len(value['files'])}


def create(root):
    root = Path(root); path = root / 'freeze.json'
    draft_bytes = (canonical(DRAFT) + '\n').encode()
    if path.exists() and path.read_bytes() != draft_bytes:
        raise ValueError('FREEZE_IS_IMMUTABLE_CREATE_NEW_METHOD_VERSION')
    method = json.loads((root / 'methodology.json').read_text())
    if (method.get('status') != 'FROZEN' or method.get('unknown_allowance_exception') is not True
            or method.get('live_enabled') is not True):
        raise ValueError('METHOD_MUST_BE_EXPLICITLY_FROZEN_FIRST')
    value = {'methodology': 'repo-wide-readonly-v1.0.0', 'status': 'FROZEN',
             'files': inventory(root), 'workflows': workflows(root)}
    if path.exists():
        if path.read_bytes() != draft_bytes: raise ValueError('DRAFT_CHANGED_DURING_FREEZE')
        temporary = path.with_suffix('.pending')
        with temporary.open('x') as stream: stream.write(canonical(value) + '\n')
        if path.read_bytes() != draft_bytes:
            temporary.unlink(); raise ValueError('DRAFT_CHANGED_DURING_FREEZE')
        os.replace(temporary, path)
    else:
        with path.open('x') as stream: stream.write(canonical(value) + '\n')
    verify(root)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('operation', choices=['create', 'verify'])
    parser.add_argument('--root', type=Path, default=Path(__file__).parent); args = parser.parse_args()
    if args.operation == 'create': create(args.root)
    else: print(canonical(verify(args.root)))
