"""Public-engine-only rg crash isolation; no captured client is executed."""
from pathlib import Path
import argparse,hashlib,json,os,resource,shutil,subprocess,sys
sys.dont_write_bytecode=True
from source_runtime import pin

def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--arch',required=True);ap.add_argument('--runtime',type=Path,required=True);ap.add_argument('--sha256',required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    runtime=a.runtime.resolve();qualified=pin(a.arch,runtime,a.sha256)
    out=a.output.resolve();out.mkdir();shutil.copyfile(Path(__file__),out/'native-rg-debug.py')
    (out/'gdb-version.txt').write_bytes(subprocess.check_output(['gdb','--version']))
    fixture=out/'input.txt';fixture.write_bytes(b'target\nother\ntarget\n')
    environment={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':str(out),'BUN_RUNTIME_TRANSPILER_CACHE_PATH':'0'}
    variants=[('plain',['--count'],b'2\n'),('filename',['-c','-H'],str(fixture).encode()+b':2\n'),
              ('null-filename',['-c','-H','--null'],str(fixture).encode()+b'\x002\n'),
              ('hidden-null',['--hidden','--max-columns','500','-c','-H','--null'],str(fixture).encode()+b'\x002\n'),
              ('json',['--json'],None),('files',['-l','--null'],str(fixture).encode()+b'\0')]
    receipt=dict(status='started',arch=a.arch,source_runtime=qualified,captured_client_executed=False,goal_complete=False,results=[])
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE,(0,0));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    try:
        for label,flags,expected in variants:
            args=['--no-config',*flags,'target',str(fixture)]
            for attempt in range(4):
                result=subprocess.run(['rg',*args],executable=runtime,env=environment,capture_output=True,timeout=10,preexec_fn=limits)
                name=label+'-'+str(attempt)
                for field in ['stdout','stderr']:(out/(name+'.'+field)).write_bytes(getattr(result,field))
                passed=result.returncode==0 and not result.stderr and (expected is None or result.stdout==expected)
                row=dict(case=label,attempt=attempt,argv=args,exit_code=result.returncode,passed=passed,
                    stdout_hex=result.stdout.hex(),stderr_hex=result.stderr.hex(),rlimit_fsize=0)
                receipt['results'].append(row);print(json.dumps(row),flush=True)
                if result.returncode==-11 and not (out/(label+'-gdb.log')).exists():
                    gdb=shutil.which('gdb');assert gdb,'GDB is required for a source-engine crash'
                    command=[gdb,'-nx','--batch','-iex','set auto-load off','-ex','set pagination off',
                        '-ex','set environment ARGV0 rg','-ex','handle SIGSEGV stop print nopass','-ex','run',
                        '-ex','thread apply all bt 30','-ex','info registers','-ex','x/24i $pc-32','--args',str(runtime),*args]
                    (out/(label+'-gdb-command.json')).write_text(json.dumps(command,indent=2)+'\n')
                    with (out/(label+'-gdb.log')).open('xb') as stream:
                        traced=subprocess.run(command,env=environment,stdout=stream,stderr=subprocess.STDOUT,timeout=45)
                    row['gdb_exit_code']=traced.returncode
        receipt['status']='public_rg_controls_passed' if all(row['passed'] for row in receipt['results']) else 'public_rg_failure_observed_not_accepted'
        assert all(row['passed'] for row in receipt['results']),'Public rg crash/output mismatch; inspect the exact retained result and stack'
    finally:
        assert sha(runtime)==a.sha256
        (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
if __name__=='__main__':main()
