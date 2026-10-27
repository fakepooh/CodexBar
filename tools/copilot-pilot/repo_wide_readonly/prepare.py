"""GitHub-hosted preparation only: full trees and complete cumulative diffs."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from .snapshot import build, canonical, sha


def hosted():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('GITHUB_REPOSITORY') != 'fakepooh/CodexBar'):
        raise ValueError('GitHub-hosted execution on exact repository required')


def prepare(output, fixture=False, case_id=None):
    hosted()
    output = Path(output); output.mkdir(parents=True, exist_ok=False)
    if fixture:
        root = output / 'snapshot'; (root / 'source').mkdir(parents=True)
        (root / 'source/example.txt').write_text(
            'Fixture, not a benchmark or defect\nOFFLINE_FIXTURE_CONTENT\n'
            'Authorization: Bearer ${SYNTHETIC_PLACEHOLDER_NOT_A_SECRET}\n')
        (root / 'source/large.txt').write_text(('PROBE_SOURCE_CHUNK_' + 'x' * 580 + '\n') * 120)
        (root / 'config.txt').write_text('fixture=true\n')
        rows = []
        import hashlib
        for path in sorted(p for p in root.rglob('*') if p.is_file()):
            content = path.read_bytes()
            rows.append({'path': str(path.relative_to(root)), 'git_mode': '100644',
                         'blob_oid': hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest(),
                         'sha256': sha(content), 'bytes': len(content)})
        receipt = {'complete': True, 'files': rows, 'file_count': len(rows), 'fixture_only': True}
        (output / 'snapshot.json').write_text(canonical(receipt))
        (output / 'snapshot.json').chmod(0o444)
        for path in sorted(root.rglob('*'), reverse=True):
            path.chmod(0o555 if path.is_dir() else 0o444)
        root.chmod(0o555)
        return
    manifest = json.loads((Path(__file__).parent / 'manifest.json').read_text())
    cases = manifest['cases']
    if [c['id'] for c in cases] != [f'PUB-{n:02}' for n in range(1, 11)]:
        raise ValueError('Exact ten-case inventory required')
    if case_id is not None:
        cases = [c for c in cases if c['id'] == case_id]
        if not cases:
            raise ValueError('Unauthorized case')
    repos = {}
    for name in sorted({c['repository'] for c in cases}):
        if name not in ('fakepooh/CodexBar', 'fakepooh/homebridge-gree-airconditioner'):
            raise ValueError('Outside authorized repositories')
        repo = output / 'objects' / name.split('/')[1]; repo.parent.mkdir(parents=True, exist_ok=True)
        commands = [
            ['git', '-c', 'core.hooksPath=/dev/null', 'init', '--bare', str(repo)],
            ['git', '-c', 'credential.helper=', '-c', 'core.hooksPath=/dev/null',
             '-c', 'protocol.file.allow=never', '-c', 'protocol.ext.allow=never', '-C', str(repo),
             'fetch', '--no-tags', '--no-recurse-submodules', 'https://github.com/' + name + '.git',
             *sorted({c[k] for c in cases if c['repository'] == name for k in ('base', 'head')})],
        ]
        for command in commands:
            result = subprocess.run(command, capture_output=True, timeout=300)
            if result.returncode:
                raise ValueError('Historical public object fetch failed')
        repos[name] = repo
    summary = []
    for case in cases:
        directory = output / case['id']; directory.mkdir()
        receipt, diff = build(repos[case['repository']], case, directory / 'snapshot')
        (directory / 'snapshot.json').write_text(canonical(receipt))
        (directory / 'snapshot.json').chmod(0o444)
        (directory / 'complete.diff').write_bytes(diff)
        summary.append({'case': case['id'], 'snapshot_sha256': receipt['snapshot_sha256'],
                        'diff_sha256': receipt['diff_sha256'], 'file_count': receipt['file_count'],
                        'snapshot_bytes': receipt['bytes'], 'diff_bytes': len(diff), 'complete': True})
    (output / 'summary.json').write_text(canonical({'cases': summary, 'real_model_requests': 0}))
    print(canonical({'status': 'PASS', 'cases': summary, 'real_model_requests': 0}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fixture', action='store_true'); parser.add_argument('--case'); args = parser.parse_args()
    try:
        prepare(args.output, args.fixture, args.case)
    except Exception:
        print(canonical({'status': 'BLOCKED', 'reason': 'INCOMPLETE_OR_UNVERIFIED_SNAPSHOT', 'real_model_requests': 0}))
        raise SystemExit(2)
