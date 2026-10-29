"""Fixed JSON-line broker process. Only trusted host gets probe/audit commands."""
import json
import os
from pathlib import Path
import re
import sys

from .broker import Broker


def os_proof(root):
    status = Path('/proc/self/status').read_text()
    mounts = Path('/proc/self/mountinfo').read_text().splitlines()
    def readonly(path):
        return any(row.split()[4] == path and 'ro' in row.split()[5].split(',') for row in mounts)
    forbidden = [k for k in os.environ if re.search(r'TOKEN|SECRET|PASSWORD|API_KEY', k, re.I)]
    return {'nonroot': os.getuid() != 0, 'root_readonly': readonly('/'),
            'snapshot_mount_readonly': readonly(str(root)),
            'no_capabilities': bool(re.search(r'^CapEff:\s*0+$', status, re.M)),
            'no_new_privileges': bool(re.search(r'^NoNewPrivs:\s*1$', status, re.M)),
            'credential_env_absent': not forbidden,
            'no_docker_socket': not Path('/var/run/docker.sock').exists(),
            'host_home_hidden': not Path('/home/runner').exists(),
            'snapshot_git_absent': not (root / '.git').exists()}


def main():
    root, receipt = Path(sys.argv[1]), Path(sys.argv[2])
    broker = Broker(root, json.loads(receipt.read_text()))
    calls = 0
    while True:
        line = sys.stdin.buffer.readline(1048577)
        if not line:
            return
        if len(line) > 1048576 or not line.endswith(b'\n'):
            return
        ident = None
        try:
            request = json.loads(line); ident = request['id']
            if type(ident) is not int or ident < 1:
                raise ValueError('Protocol ID')
            tool = request['tool']
            if tool == '__probe__':
                result = os_proof(root)
            elif tool == '__audit__':
                result = {'calls': broker.calls}
            else:
                calls += 1
                if calls > 200:
                    raise ValueError('Tool budget exhausted')
                result = broker.call(tool, request['arguments'])
            response = {'id': ident, 'ok': True, 'result': result}
        except Exception:
            response = {'id': ident, 'ok': False, 'error': 'SNAPSHOT_ACCESS_DENIED_OR_LIMIT'}
        data = json.dumps(response, ensure_ascii=False)
        if len(data.encode()) > 1048576:
            data = json.dumps({'id': ident, 'ok': False, 'error': 'EXPLICIT_RESPONSE_LIMIT'})
        print(data, flush=True)


if __name__ == '__main__': main()
