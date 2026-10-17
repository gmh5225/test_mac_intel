"""Observe native Windows roles after the same authored OS-boundary controls."""
from pathlib import Path
import argparse,base64,hashlib,json,os,shutil,struct,tarfile,urllib.request
from client_acceptance import PINS
from contained_protocol import ContainedProtocol
from core_tool_acceptance import fresh_root,sha,write

ROOT=Path(__file__).resolve().parent
def utf16_hex(value):
    raw=value.encode('utf-16-le')
    return ''.join(f'{int.from_bytes(raw[i:i+2],"little"):04x}' for i in range(0,len(raw),2))
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--arch',required=True,choices=['x64','arm64']);ap.add_argument('--environment',type=Path,required=True);a=ap.parse_args()
    out=a.environment.resolve();logs=out/'evidence';qualified=json.loads((logs/'receipt.json').read_bytes())
    assert qualified['status']=='authored_windows_environment_qualified' and qualified['authored_inputs_only'] and not qualified['captured_client_executed']
    assert qualified['architecture']==a.arch and qualified['isolation']['status']=='qualified'
    assert os.name=='nt'
    transport=out/'role-transport.exe';assert transport.is_file()
    raw=transport.read_bytes();pe=struct.unpack_from('<I',raw,60)[0]
    assert raw[:2]==b'MZ' and raw[pe:pe+4]==b'PE\0\0' and struct.unpack_from('<H',raw,pe+4)[0]=={'x64':0x8664,'arm64':0xaa64}[a.arch]
    report=logs/'native-roles';report.mkdir()
    receipt=dict(status='started',arch=a.arch,authored_controls=[],observations=[],environment_receipt_sha256=sha(logs/'receipt.json'),launcher_sha256=sha(out/'appcontainer-run.exe'),transport_sha256=sha(transport),transport_source_sha256=sha(ROOT/'role-transport.cpp'),driver_sha256=sha(Path(__file__)),goal_complete=False)
    def observe(label,source,argv0,role,args,*,receiver=False,preprocessor=False):
        root=fresh_root();shutil.copyfile(transport,root/'bin/transport.exe');shutil.copyfile(source,root/'bin/target.exe')
        assert sha(root/'bin/target.exe')==sha(source) and sha(root/'bin/transport.exe')==sha(transport)
        assert not (receiver and preprocessor)
        if receiver or preprocessor:
            shutil.copyfile(transport,root/'bin/receiver.exe');assert sha(root/'bin/receiver.exe')==sha(transport)
            fixture=root/'work/owned-猫.txt';fixture.write_bytes(b'owned NEEDLE\n')
            args=[str(fixture)] if receiver else ['--no-config','--no-filename','--fixed-strings','--pre',str(root/'bin/receiver.exe'),'-e','"kind":"owned-rg-preprocessor"','-e','owned NEEDLE',str(fixture)]
        env={k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','COMSPEC','SYSTEMDRIVE'}}
        env.update(HOME=str(root/'home'),USERPROFILE=str(root/'home'),APPDATA=str(root/'home'),LOCALAPPDATA=str(root/'home'),TEMP=str(root/'tmp'),TMP=str(root/'tmp'),CLAUDE_CONFIG_DIR=str(root/'home/.claude'),CLAUDE_CODE_TMPDIR=str(root/'tmp'),BUN_RUNTIME_TRANSPILER_CACHE_PATH='0',NO_COLOR='1',CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1',DISABLE_AUTOUPDATER='1',ENABLE_CLAUDEAI_MCP_SERVERS='false',PATH=str(Path(os.environ['SystemRoot'])/'System32'))
        if role is not None:env['ARGV0']=role
        p=report/label;p.mkdir();write(p/'arguments.json',dict(argv0=argv0,role=role,args=args))
        t=ContainedProtocol(out/'appcontainer-run.exe',root,env,'transport.exe',[root/'bin/target.exe',argv0,*args],p,'process')
        try:execution=t.finish()
        finally:t.retain()
        assert execution['app_container'] and execution['capability_count']==0 and execution['remaining_processes']==0
        assert not execution['timeout'] and not execution['output_limit'] and not execution['loopback_exemption']
        assert execution['loopback_exemption_removed'] and execution['null_device_grant_removed']
        stdout=(p/'process.stdout').read_bytes();stderr=(p/'process.stderr').read_bytes()
        row=dict(case=label,argv0=argv0,role=role,execution=execution,stdout=stdout.decode('utf-8'),stderr=stderr.decode('utf-8'),stdout_sha256=hashlib.sha256(stdout).hexdigest(),stderr_sha256=hashlib.sha256(stderr).hexdigest())
        if receiver or preprocessor:
            lines=stdout.splitlines(keepends=True)
            assert execution['exit_code']==0 and not stderr and len(lines)==2 and lines[1]==b'owned NEEDLE\n'
            child=json.loads(lines[0]);assert child['kind']=='owned-rg-preprocessor' and child['input_utf16_hex']==utf16_hex(str(fixture))
            assert set(child)=={'kind','input_utf16_hex','env_utf16_hex'};row['child_environment']=child
        return row
    try:
        for i,(argv0,role) in enumerate([('owned-α 🐈',None),('rg.exe','unknown'),('C:\\owned path\\ugrep.exe','rg')]):
            row=observe('authored-'+str(i),transport,argv0,role,['--capture'])
            assert row['execution']['exit_code']==37 and not row['stderr']
            assert json.loads(row['stdout'])==dict(argv0_utf16_hex=utf16_hex(argv0),env_utf16_hex=None if role is None else utf16_hex(role))
            receipt['authored_controls'].append(row)
        receiver_baselines=[]
        for i,role in enumerate([None,'','rg','unknown','ugrep','猫']):
            row=observe('authored-receiver-'+str(i),transport,'receiver.exe',role,[],receiver=True)
            value=row['child_environment']['env_utf16_hex']
            if role=='':assert value in [None,'']
            else:assert value==(None if role is None else utf16_hex(role))
            receiver_baselines.append(value);receipt['authored_controls'].append(row)
        write(report/'qualified-before-original.json',receipt)
        archive=out/'published-role-input.tgz';pins=PINS[a.arch]
        with urllib.request.urlopen(f'https://registry.npmjs.org/@anthropic-ai/claude-code-win32-{a.arch}/-/claude-code-win32-{a.arch}-2.1.296.tgz',timeout=90) as response:
            data=response.read(160*1024*1024+1)
        assert len(data)<=160*1024*1024 and hashlib.sha512(data).digest()==base64.b64decode(pins['integrity']);archive.write_bytes(data)
        original=out/'role-original.exe'
        with tarfile.open(archive,'r:gz') as t:
            m=t.getmember('package/claude.exe');assert m.isfile() and m.size<300*1024*1024
            original.write_bytes(t.extractfile(m).read())
        assert sha(original)==pins['original'];receipt['original_sha256']=sha(original)
        cases=[('absent','owned-client',None),('empty','owned-client',''),('unknown','owned-client','unknown'),
            *[('env-'+role,'owned-client',role) for role in ['rg','ug','ugrep','bfs','apply-seccomp']],
            ('env-path','owned-client','C:\\fixture\\rg.exe'),('env-uppercase','owned-client','RG'),
            *[('actual-'+role,role,'unknown') for role in ['rg','ug','ugrep','bfs','apply-seccomp']],
            ('actual-posix-path','/fixture/rg','ugrep'),('actual-exe','rg.exe','ugrep'),
            ('actual-uppercase-exe','RG.EXE','ugrep'),('actual-windows-path','C:\\fixture\\rg.exe','ugrep'),
            ('actual-windows-no-suffix','C:\\fixture\\rg','ugrep'),('actual-trailing-slash','C:\\fixture\\rg\\','ugrep'),
            ('actual-unknown-fallback','owned-client','rg')]
        for label,argv0,role in cases:
            row=observe(label,original,argv0,role,['--version']);receipt['observations'].append(row)
            write(report/'receipt.json',receipt);print(json.dumps(row),flush=True)
        receipt['child_environment_observations']=[]
        for i,role in enumerate([None,'','rg','unknown','ugrep','猫']):
            row=observe('original-rg-child-'+str(i),original,'rg.exe',role,[],preprocessor=True)
            before=receiver_baselines[i];after=row['child_environment']['env_utf16_hex']
            assert after is None or after==before,'Unexpected child environment mutation'
            row.update(authored_environment_utf16_hex=before,consumption_observable=before is not None,argv0_consumed=None if before is None else after is None)
            receipt['child_environment_observations'].append(row);write(report/'receipt.json',receipt);print(json.dumps(row),flush=True)
        assert sha(original)==pins['original']
        receipt.update(status='native_windows_role_observations_recorded',input_preserved=True,scope='Native original process observations under a qualified capability-free AppContainer. No Linux or macOS role/path rules are assumed; original runtime rebuild equivalence is not established.')
    except BaseException as error:
        receipt.update(status='failed',error=str(error));raise
    finally:write(report/'receipt.json',receipt)
if __name__=='__main__':main()
