"""Bounded trusted child execution, including inherited-pipe descendants."""
import os
import signal
import subprocess


def run(command, *, data, env, timeout):
    process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,env=env,start_new_session=True)
    try:
        out,err=process.communicate(data,timeout=timeout)
        return subprocess.CompletedProcess(command,process.returncode,out,err)
    except BaseException as exc:
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        try:out,err=process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.stdout.close();process.stderr.close();process.wait(timeout=5)
            out,err=b'',b''
        if isinstance(exc,subprocess.TimeoutExpired):
            # Do not include command, prompt, environment or stdin in diagnostics.
            raise subprocess.TimeoutExpired('offline-child; arguments withheld',timeout,
                                            output=out,stderr=err) from None
        raise
