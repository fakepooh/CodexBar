"""Fetch exact public objects into disposable bare caches; never checkout or execute them."""
import argparse
from pathlib import Path
import subprocess
import os
import signal
import time
import public_series as series
import pilot as p

def fetch(directory, name, shas):
    env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')
         and not any(word in k.upper() for word in ('TOKEN','SECRET','PASSWORD','API_KEY'))
         and k != 'SSH_AUTH_SOCK'}
    env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0')
    command=['git','--no-replace-objects','-c','core.hooksPath=/dev/null',
             '-c','core.fsmonitor=false','-C',str(directory),'fetch','--depth=32',
             '--no-tags','--no-recurse-submodules','https://github.com/'+name+'.git',*shas]
    started=time.monotonic()
    process=subprocess.Popen(command,env=env,stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                             start_new_session=True)
    try:
        code=process.wait(timeout=120)
    except BaseException:
        os.killpg(process.pid,signal.SIGTERM)
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
        raise ValueError('Bounded exact-object fetch failed; no automatic retry') from None
    if code:raise ValueError('Exact public object fetch failed; no automatic retry')
    return round(time.monotonic()-started,3)

def main(output):
    rows=series.cases(series.SERIES/'manifest.json');repos={}
    for name in sorted({c['repository'] for c in rows}):
        directory=output/name.split('/')[1]
        if directory.exists(): raise ValueError('Require fresh object cache')
        directory.parent.mkdir(parents=True,exist_ok=True)
        subprocess.run(['git','-c','core.hooksPath=/dev/null','init','--bare',str(directory)],check=True,capture_output=True)
        shas=sorted({c[k] for c in rows if c['repository']==name for k in ('base','head')})
        # Bounded ancestry, complete trees/blobs. Never replace SHA by branch heads.
        # Every exact historical base must still be a provable ancestor below.
        elapsed=fetch(directory,name,shas)
        for case in rows:
            if case['repository']==name:p.verify_case(case,directory)
        print({'repository':name,'exact_historical_ancestry':'PASS','fetch_seconds':elapsed},flush=True)
        repos[name]=str(directory.resolve())
    p.save(output/'repos.json',repos)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);main(parser.parse_args().output)
