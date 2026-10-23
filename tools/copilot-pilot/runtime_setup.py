"""Private CP-01 VM control; never calls Copilot or handles credentials."""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent


def context_mount(case_id):
    # One explicit sealed case, never a parent directory or arbitrary host path.
    import pilot
    case = next((c for c in pilot.cases() if c['id'] == case_id), None)
    if case is None:
        raise ValueError('Unknown historical case')
    context = ROOT / 'contexts' / case_id
    pilot.check_context(context, case)
    return context


def environment():
    state = json.loads((ROOT / '.cache/runtime-state.json').read_text())
    runtime = Path(state['root'])
    if runtime.is_symlink() or runtime.stat().st_uid != os.getuid() or runtime.stat().st_mode & 0o077:
        raise ValueError('Runtime state must be private and user-owned')
    for name in ['home', 'cache', 'tmp', 'docker-config', 'colima']:
        (runtime / name).mkdir(mode=0o700, exist_ok=True)
    env = {'PATH': str(ROOT / '.cache/components/bin') + ':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',
           'HOME': str(runtime / 'home'), 'COLIMA_HOME': str(runtime / 'colima'),
           'COLIMA_CACHE_HOME': str(runtime / 'cache'), 'XDG_CACHE_HOME': str(runtime / 'cache'),
           'LIMA_HOME': str(runtime / 'lima'), 'DOCKER_CONFIG': str(runtime / 'docker-config'),
           'TMPDIR': str(runtime / 'tmp'), 'LANG': 'en_US.UTF-8'}
    return state, env


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['start', 'status', 'stop'])
    parser.add_argument('--case', default='CP-01')
    parser.add_argument('--evidence', type=Path, default=ROOT / 'evidence/cp01-authorized-2026-10-18')
    args = parser.parse_args()
    state, env = environment()
    cmd = ['colima', '--profile', state['profile'], args.action]
    if args.action == 'start':
        context = context_mount(args.case)
        # Colima 0.10.3 emits a [0,0] ignore range for port-forwarder=none.
        # Explicit Lima override takes precedence and covers all TCP/UDP ports.
        config = Path(env['LIMA_HOME']) / '_config'
        config.mkdir(mode=0o700, parents=True, exist_ok=True)
        (config / 'override.yaml').write_text('portForwards:\n'
            '  - guestIP: "0.0.0.0"\n'
            '    guestIPMustBeZero: false\n'
            '    guestPortRange: [1, 65535]\n'
            '    hostIP: "127.0.0.1"\n'
            '    proto: any\n'
            '    ignore: true\n')
        cmd += ['--runtime=docker', '--vm-type=vz', '--arch=aarch64', '--cpu=2',
                '--memory=4', '--disk=10', '--root-disk=10', '--activate=false',
                '--ssh-config=false', '--ssh-agent=false', '--binfmt=false',
                '--port-forwarder=none', '--network-address=false',
                '--vz-rosetta=false', '--mount-type=virtiofs', '--mount=' + str(context)]
    evidence = args.evidence
    evidence.mkdir(mode=0o700, exist_ok=True)
    # Unique output names preserve diagnostics of previous operations.
    import uuid
    log = evidence / ('vm-' + args.action + '-' + uuid.uuid4().hex + '.log')
    with log.open('x') as out:
        result = subprocess.run(cmd, env=env, stdout=out, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, timeout=600)
    print(json.dumps({'exit_code': result.returncode, 'log': str(log), 'ai_invocations': 0}))
    raise SystemExit(result.returncode)
