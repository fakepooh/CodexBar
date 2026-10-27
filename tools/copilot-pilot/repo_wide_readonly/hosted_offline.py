"""GitHub-hosted credential-free native probe with bounded owned-container cleanup.

No live model endpoint, session credential, prompt secret or execution ledger is used.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

from .prepare import hosted, prepare
from .snapshot import canonical, sha


def run(output):
    hosted()
    output = Path(output); output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic(); stages = []; name = 'repo-wide-offline-' + secrets.token_hex(8)
    image = 'repo-wide-offline:' + secrets.token_hex(8)
    def command(stage, argv, timeout):
        before = time.monotonic()
        try:
            result = subprocess.run(argv, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            stages.append({'stage': stage, 'seconds': round(time.monotonic() - before, 3), 'status': 'TIMEOUT'})
            raise ValueError('OFFLINE_STAGE_TIMEOUT') from None
        stages.append({'stage': stage, 'seconds': round(time.monotonic() - before, 3),
                       'status': 'PASS' if result.returncode == 0 else 'FAILED'})
        if result.returncode:
            # Never print dependency, CLI or Docker raw errors into public logs.
            raise ValueError('OFFLINE_STAGE_FAILED')
        return result.stdout
    report = {'status': 'BLOCKED', 'real_model_requests': 0, 'live_reservations_created': 0}
    try:
        prepare(output / 'fixture', fixture=True)
        context = Path(__file__).resolve().parent
        command('image_build', ['docker', 'build', '--pull=false', '-t', image, str(context)], 600)
        raw = command('native_cli_broker_transport', ['docker', 'run', '--name', name, '--network=none',
            '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--user=65534:65534',
            '--pids-limit=128', '--memory=2g', '--cpus=2', '--init',
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777',
            '--mount', 'type=bind,src=' + str((output / 'fixture/snapshot').resolve()) + ',dst=/snapshot,readonly',
            '--mount', 'type=bind,src=' + str((output / 'fixture/snapshot.json').resolve()) + ',dst=/metadata/snapshot.json,readonly',
            image], 150)
        proof = json.loads(raw)
        if (proof.get('status') != 'PASS' or proof.get('native_cli_version') != '1.0.98'
                or type(proof.get('real_model_requests')) is not int or proof['real_model_requests'] != 0
                or type(proof.get('mock_requests')) is not int or proof['mock_requests'] != 6
                or proof.get('exact_tool_results_received') is not True
                or proof.get('host_escape_denied') is not True
                or proof.get('local_receiver_authenticated') is not True
                or proof.get('exact_tool_result_order_verified') is not True
                or not proof.get('os_isolation') or not all(v is True for v in proof['os_isolation'].values())):
            raise ValueError('NATIVE_OFFLINE_RECEIPT_REJECTED')
        (output / 'native-proof.json').write_text(canonical(proof))
        report['status'] = 'PASS'; report['native_proof_sha256'] = sha(canonical(proof).encode())
    except (ValueError, OSError, json.JSONDecodeError):
        report['reason'] = 'HOSTED_NATIVE_OFFLINE_PROOF_INCOMPLETE'
    finally:
        # Only the unique container owned by this invocation, including deadline failures.
        report['owned_container_absent_after_cleanup'] = False
        try:
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=30)
            inventory = subprocess.run(['docker', 'ps', '-a', '--format', '{{.Names}}'],
                                       capture_output=True, timeout=30)
            report['owned_container_absent_after_cleanup'] = (
                inventory.returncode == 0 and name not in inventory.stdout.decode().splitlines())
        except (OSError, subprocess.TimeoutExpired):
            pass
        if not report['owned_container_absent_after_cleanup']:
            report['status'] = 'BLOCKED'; report['reason'] = 'CONTAINER_CLEANUP_UNPROVED'
        report['stages'] = stages; report['seconds'] = round(time.monotonic() - started, 3)
        (output / 'receipt.json').write_text(canonical(report))
        print(canonical(report))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(0 if run(args.output)['status'] == 'PASS' else 2)
