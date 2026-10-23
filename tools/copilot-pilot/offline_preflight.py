"""CP-01 readiness only. Never authenticates, pulls images, or sends prompts."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid

import pilot as p


# Trusted probe code, never code from the historical repository.
PROBE = r"""
const fs = require('fs'), cp = require('child_process'), os = require('os');
const checks = {};
checks.unprivileged = process.getuid() === 65532;
checks.context_readable = fs.readFileSync('/context/context.json').length > 0;
const mounts = fs.readFileSync('/proc/self/mountinfo', 'utf8').trim().split('\n').map(x => x.split(' '));
checks.root_mount_readonly = mounts.some(x => x[4] === '/' && x[5].split(',').includes('ro'));
checks.context_mount_readonly = mounts.some(x => x[4] === '/context' && x[5].split(',').includes('ro'));
function denied(path) {
  try { fs.writeFileSync(path, 'probe', {flag:'wx'}); return false; }
  catch (e) { if (!['EROFS','EACCES','EPERM'].includes(e.code)) throw e; return true; }
}
checks.root_readonly = denied('/cp01-probe');
checks.context_readonly = denied('/context/cp01-probe');
checks.host_sentinel_hidden = !fs.existsSync(process.argv[1]);
checks.host_home_hidden = !fs.existsSync('/Users/pooh');
checks.no_docker_socket = !fs.existsSync('/var/run/docker.sock');
checks.ephemeral_home = fs.readdirSync('/home/copilot').length === 0;
checks.no_credentials = !Object.keys(process.env).some(k => /TOKEN|SECRET|API_KEY/.test(k));
checks.network_none = Object.values(os.networkInterfaces()).flat().every(x => x.internal);
const status = fs.readFileSync('/proc/self/status', 'utf8');
checks.no_new_privileges = /^NoNewPrivs:\s+1$/m.test(status);
checks.no_capabilities = /^CapEff:\s+0+$/m.test(status);
fs.writeFileSync('/tmp/cp01-probe', '#!/bin/sh\nexit 0\n', {mode:0o700});
try { cp.execFileSync('/tmp/cp01-probe'); checks.tmp_noexec = false; }
catch (e) { checks.tmp_noexec = e.code === 'EACCES'; }
console.log(JSON.stringify(checks));
if (!Object.values(checks).every(x => x === true)) process.exitCode = 1;
"""


def command(image, context, endpoint, args, entrypoint='copilot', name=None):
    # Never silently select a shared/default Docker daemon or accept TCP.
    if not endpoint.startswith('unix:///') or any(c in endpoint for c in '\n\r\0'):
        raise ValueError('Explicit private unix:/// Docker socket required')
    cmd = p.docker_base(image, context)
    cmd[1:1] = ['--host=' + endpoint]
    cmd[cmd.index('--entrypoint=copilot')] = '--entrypoint=' + entrypoint
    if name:
        cmd.insert(cmd.index('run') + 1, '--name=' + name)
    return cmd + [image, *args]


def run_probe(image, context, endpoint, args, env, entrypoint='copilot'):
    name = 'cp01-offline-preflight-' + uuid.uuid4().hex
    try:
        return subprocess.run(command(image, context, endpoint, args, entrypoint, name),
                              env=env, capture_output=True, text=True, timeout=60)
    finally:
        subprocess.run(['docker', '--host=' + endpoint, 'rm', '-f', name],
                       env=env, capture_output=True, text=True, timeout=30)
        absent = subprocess.run(['docker', '--host=' + endpoint, 'ps', '-aq',
            '--filter=name=^/' + name + '$'], env=env,
            capture_output=True, text=True, timeout=30)
        if absent.returncode or absent.stdout.strip():
            raise ValueError('Container removal could not be verified')


def inspect(context, image=None, endpoint=None, case_id='CP-01'):
    case = next(c for c in p.cases() if c['id'] == case_id)
    meta = p.check_context(context, case)
    report = {'checked_at': p.now(), 'case': case_id,
              'context_sha256': meta['context_sha256'], 'ai_invocations': 0,
              'authorization_used': False, 'static_context': 'passed',
              'runtime': 'blocked', 'live_ready': False}
    if not shutil.which('docker'):
        report['blocker'] = 'Docker CLI unavailable; no host Copilot fallback'
        return report
    if not image or not endpoint:
        report['blocker'] = 'Verified immutable image and explicit private Docker socket required'
        return report
    # Validate arguments before any subprocess.
    command(image, context, endpoint, ['--version'])
    with tempfile.TemporaryDirectory(prefix='cp01-preflight-') as tmp:
        env = p.clean_env()
        env.update(HOME=tmp, DOCKER_CONFIG=tmp)
        sentinel = Path(tmp) / 'host-only-sentinel'
        sentinel.write_text('synthetic host marker; no secrets')
        try:
            version = None
            for args in (['--version'], [*p.FLAGS, '--help']):
                r = run_probe(image, context, endpoint, args, env)
                if r.returncode:
                    raise ValueError('Network-disabled CLI metadata probe failed')
                if args == ['--version']:
                    version = r.stdout.strip()
                    if not re.search(r'(?<![\d.])1\.0\.98(?![\w+-]|\.\d)', version):
                        raise ValueError('Expected pinned CLI 1.0.98')
                elif any(flag not in r.stdout for flag in
                         [x.split('=')[0] for x in p.FLAGS] + ['--max-ai-credits', '--prompt']):
                    raise ValueError('Pinned CLI lacks required safety flags')
            probe = run_probe(image, context, endpoint,
                              ['-e', PROBE, str(sentinel)], env, entrypoint='node')
            if probe.returncode:
                raise ValueError('Runtime isolation probe failed')
            checks = json.loads(probe.stdout)
            required = {'unprivileged', 'context_readable', 'root_readonly', 'context_readonly',
                        'root_mount_readonly', 'context_mount_readonly',
                        'host_sentinel_hidden', 'host_home_hidden', 'no_docker_socket',
                        'ephemeral_home', 'no_credentials', 'network_none',
                        'no_new_privileges', 'no_capabilities', 'tmp_noexec'}
            if not isinstance(checks, dict) or set(checks) != required or not all(v is True for v in checks.values()):
                raise ValueError('Runtime isolation checks failed')
            p.check_context(context, case)
            report.update(runtime='passed', cli_version=p.scrub(version), image=image,
                          checks=checks, container_removed=True,
                          cli_help_sha256=p.digest(r.stdout.encode()),
                          required_flags_verified=[x.split('=')[0] for x in p.FLAGS] +
                                                  ['--max-ai-credits', '--prompt'])
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            # No raw CLI output or environment in the report.
            report['blocker'] = type(exc).__name__ + ': ' + p.scrub(str(exc))
    # Offline probes cannot prove /review compatibility or budget sufficiency.
    report['remaining_gates'] = ['human AI authorization', 'dedicated credential',
                                'budget decision', 'built-in review engine verification on live output']
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, default=p.ROOT / 'contexts/CP-01')
    parser.add_argument('--case', default='CP-01')
    parser.add_argument('--image')
    parser.add_argument('--docker-host')
    parser.add_argument('--out', type=Path, required=True)
    a = parser.parse_args()
    result = inspect(a.context, a.image, a.docker_host, a.case)
    if a.out.exists():
        parser.error('Use a new output filename; prior evidence is preserved')
    p.save(a.out, result)
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result['runtime'] == 'passed' else 2)
