"""Native Mac client differential cases; private inputs stay outside public logs."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'windows-recovery'))
sys.path.insert(0, str(ROOT.parent / 'seccomp-helper'))
from compare_bash import Normalize, differences
from offline_server import OfflineServer
from sequence_fixture_controls import SPEC, check_sequence_fixture
from client_protocol import run as protocol, matches
from bounded_process import run as bounded
from client_build import critical_sections
from source_engine import qualify as qualify_engine

SID = '00000000-0000-4000-8000-000000000001'
MATRICES = {'search': ('search-tool-cases.json', '34e694c01daae7d1fbc9f053c96b48e588d07c381ee514ae49b02907e981fa7e'),
            'core': ('core-tool-cases.json', '0e248970f6e292bb07d2144f5970f997dca515f9b434a4c4a216ff978d74f41c')}
MODELS = dict(user='claude-sonnet-4-5-20250929', project='claude-sonnet-5', local='claude-sonnet-5-5',
    flag='claude-opus-5-5', cli='claude-haiku-5-5', empty_sources='claude-opus-5-5', bad_local='claude-sonnet-5')


def sha(path):
    with Path(path).open('rb') as file: return hashlib.file_digest(file, 'sha256').hexdigest()


def write(path, value): path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def arguments(tools='', model='claude-sonnet-5'):
    return ['-p', '--output-format', 'stream-json', '--verbose', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}',
        '--no-chrome', '--disable-slash-commands', '--permission-mode', 'manual', '--permission-prompts', 'none',
        '--system-prompt', 'Offline fixture. Use only supplied fixture data.', '--setting-sources', '',
        '--tools', tools, '--allowedTools', tools, '--model', model, '--session-id', SID]


def initialize():
    return [dict(send_json=dict(type='control_request', request_id='init-1', request=dict(subtype='initialize'))),
        dict(wait_json={'type':'control_response', 'response.request_id':'init-1', 'response.subtype':'success'})]


class Harness:
    def __init__(self, arch, original, engine, build_receipt, output, logs):
        assert platform.system() == 'Darwin' and platform.machine() == {'arm64':'arm64', 'x64':'x86_64'}[arch] and os.getuid() != 0
        assert subprocess.run(['/usr/sbin/sysctl','-n','sysctl.proc_translated'],capture_output=True).stdout != b'1\n'
        self.arch = arch; self.original = original; self.engine = engine; self.output = output; self.logs = logs
        engine_receipt = json.loads(json.dumps(qualify_engine(arch, engine)))
        self.icu = sorted(p for p in Path('/usr/share/icu').glob('icudt*l.dat') if re.fullmatch(r'icudt[0-9]+l\.dat',p.name))
        assert self.icu and all(p.is_file() and not p.is_symlink() and p.stat().st_size < 64*1024*1024 for p in self.icu)
        self.timezone = sorted(Path('/var/db/timezone/icutz').glob('icutz*l.dat'))
        assert self.timezone and all(re.fullmatch(r'icutz[0-9]+l\.dat',p.name) and p.is_file() and p.stat().st_size < 16*1024*1024
            and p.resolve().as_posix().startswith('/private/var/db/timezone/tz/') for p in self.timezone)
        build = json.loads(build_receipt.read_bytes())
        assert build['arch'] == arch and build['status'] == 'both_Mac_source_engine_clients_rebuilt_and_2609_rows_readback_exactly'
        assert build['all_2609_original_rows_match_prior_NeverD'] and build['original_descriptor_provider_preserved']
        assert not build['original_caches_reused'] and not build['source_engine']['original_prefix_used']
        assert build['source_engine'] == engine_receipt
        pin = json.loads((ROOT/'original-pins.json').read_bytes())[arch]
        assert sha(original) == pin['sha256'] == build['original_sha256'] and original.stat().st_size == pin['bytes']
        self.clients = dict(original=original)
        for label, row in build['clients'].items():
            client = Path(row['path']); assert sha(client) == row['sha256'] and client.stat().st_size == row['bytes']
            assert row['all_module_rows_match_selected_source'] and not row['intentionally_edited_modules']
            assert critical_sections(client) == critical_sections(engine) == row['source_engine_code_and_exception_sections_preserved']
            self.clients[label] = client
        output.mkdir(); logs.mkdir(); self.private = output/'private-records'; self.private.mkdir()
        self.inputs = output/'owned-inputs'; self.inputs.mkdir()
        self.runtime = output/'runtime'; self.runtime.mkdir()
        for label, source in list(self.clients.items()):
            target = self.runtime/('client-'+label)
            subprocess.run(['/bin/cp','-c',source,target],check=True,timeout=30); target.chmod(0o500)
            assert sha(target) == sha(source); self.clients[label] = target
        self.engine = self.runtime/'bun'; subprocess.run(['/bin/cp','-c',engine,self.engine],check=True,timeout=30); self.engine.chmod(0o500)
        assert sha(self.engine) == engine_receipt['binary_sha256']
        self.boundary = self.runtime/'boundary'; self.transport = self.runtime/'transport'; self.runner = self.runtime/'runner-control'
        for source, target in [('boundary-control.c', self.boundary), ('role-transport.c', self.transport), ('client-runner-control.c',self.runner)]:
            result = subprocess.run(['xcrun','clang','-std=c11','-O2','-Wall','-Wextra','-Werror',str(ROOT/source),'-o',str(target)],capture_output=True,timeout=60)
            assert result.returncode == 0, 'authored control compilation failed'
        self.probe = self.inputs/'client-fixture-probe.mjs'; shutil.copyfile(ROOT/self.probe.name, self.probe)
        self.receipt = dict(status='started', arch=arch, native_host=True, runtime_os_version=platform.mac_ver()[0],
            source_engine=engine_receipt, build_receipt_sha256=sha(build_receipt), original_sha256=sha(original),
            client_sha256={label:sha(path) for label,path in self.clients.items()}, cases=[], differential_pairs=[],
            original_descriptor_provider_preserved=True, external_rg_on_PATH=False, managed_search_launcher_used=False,
            original_prefix_used=False, captured_source_uploaded=False, clients_uploaded=False, goal_complete=False)
        self.receipt['public_system_ICU_data'] = [dict(path=str(p),bytes=p.stat().st_size,sha256=sha(p)) for p in self.icu]
        self.receipt['public_system_timezone_data'] = [dict(path=str(p),resolved=str(p.resolve()),bytes=p.stat().st_size,sha256=sha(p)) for p in self.timezone]
        source = logs/'source'; source.mkdir()
        for name in ['client_acceptance.py','client_protocol.py','client_bash.py','client-fixture-probe.mjs','client-runner-control.c','boundary-control.c','role-transport.c','source_engine.py','source-engine-pins.json','original-pins.json']:
            shutil.copyfile(ROOT/name,source/name)
        shutil.copyfile(ROOT.parent/'seccomp-helper/compare_bash.py',source/'compare_bash.py')

    def profile(self, stage, target, port, capability=None):
        assert capability in [None,'bash']
        literal = lambda p:'(literal ' + json.dumps(str(p)) + ')'
        text = '(version 1)\n(deny default)\n(allow sysctl-read)\n(allow file-read-metadata)\n'
        system = '(subpath "/System/Library") (subpath "/usr/lib") (subpath "/System/Volumes/Preboot/Cryptexes/OS")'
        text += '(allow file-read* (literal "/") (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random") (subpath "/dev/fd") (subpath "/usr/share/locale") (subpath "/usr/share/zoneinfo") ' + system + ')\n'
        text += '(allow file-map-executable ' + system + ')\n'
        text += '(allow file-read* ' + ' '.join(literal(p) for p in self.icu) + ')\n'
        text += '(allow file-read* ' + ' '.join(literal(p) for file in self.timezone for p in [file,file.resolve()]) + ')\n'
        text += '(allow file-read* (subpath ' + json.dumps(str(self.inputs)) + '))\n'
        for part in ['work','home','tmp','fixtures','report']:
            text += '(allow file-read* (subpath ' + json.dumps(str(stage/part)) + '))\n'
        for part in ['work','home','tmp','report']:
            text += '(allow file-write* (subpath ' + json.dumps(str(stage/part)) + '))\n'
        for path in {target, self.engine, self.boundary, self.transport}:
            text += '(allow file-read* file-map-executable process-exec ' + literal(path) + ')\n'
        if capability == 'bash':
            text += '(allow file-write* (literal "/dev/null"))\n'
            for path in ['/bin/bash','/bin/cat']:
                text += '(allow file-read* file-map-executable process-exec ' + literal(path) + ')\n'
        text += '(allow process-fork)\n(allow signal (target self))\n'
        if port is not None: text += '(allow network-outbound (remote tcp "localhost:' + str(port) + '"))\n'
        return text

    def execute(self, name, label, argv, *, spec=None, steps=None, work_input='fixture input\n', fixture_files=None, setup=None, extra_env=None, capability=None, expected_exit_code=0):
        assert re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*',name) and label in [*self.clients,'authored']
        stage = self.output/name; stage.mkdir()
        for part in ['work','home','tmp','fixtures','report']: (stage/part).mkdir()
        (stage/'work/input.txt').write_text(work_input)
        for name_, content in (fixture_files or {}).items():
            assert Path(name_).name == name_; (stage/'fixtures'/name_).write_text(content)
        private = self.private/name; private.mkdir()
        target = self.engine if label == 'authored' else self.clients[label]
        def replace(value):
            if isinstance(value, dict): return {key:replace(item) for key,item in value.items()}
            if isinstance(value, list): return [replace(item) for item in value]
            if isinstance(value, str):
                for part in ['work','fixtures']:
                    prefix = '/' + part
                    if value == prefix or value.startswith(prefix + '/'):
                        return str(stage/part) + value[len(prefix):]
            return value
        if setup is not None: argv = setup(stage, argv)
        argv = [replace(str(value)) for value in argv]
        if spec is not None and label != 'authored': spec = replace(spec)
        server = OfflineServer(spec, private) if spec is not None else None
        if '@FIXTURE_PORT@' in argv:
            assert server is not None and label == 'authored'
            argv = [str(server.port) if value == '@FIXTURE_PORT@' else value for value in argv]
        profile = private/'profile.sb'; profile.write_text(self.profile(stage,target,server.port if server else None,capability))
        environment = dict(HOME=str(stage/'home'), TMPDIR=str(stage/'tmp'), XDG_CONFIG_HOME=str(stage/'home/config'),
            XDG_CACHE_HOME=str(stage/'home/cache'), BUN_INSTALL_CACHE_DIR=str(stage/'home/bun-cache'),
            BUN_RUNTIME_TRANSPILER_CACHE_PATH='0', PATH='/unavailable', LANG='C', LC_ALL='C', TZ='UTC', NO_COLOR='1',
            CLAUDE_CONFIG_DIR=str(stage/'home/.claude'), CLAUDE_CODE_TMPDIR=str(stage/'tmp'),
            ANTHROPIC_API_KEY='sk-ant-api03-offline-fixture-not-a-real-credential',
            ANTHROPIC_BASE_URL='http://127.0.0.1:' + str(server.port if server else 9),
            CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1',DISABLE_AUTOUPDATER='1',ENABLE_CLAUDEAI_MCP_SERVERS='false', USE_BUILTIN_RIPGREP='true')
        if capability == 'bash': environment.update(SHELL='/bin/bash',CLAUDE_CODE_SHELL='/bin/bash')
        for key,value in (extra_env or {}).items():
            assert key == 'RIPGREP_CONFIG_PATH' and value.startswith('/fixtures/'); environment[key] = replace(value)
        canary = stage/'outside-canary'; canary.write_text('owned outside canary\n')
        control_logs = private/'control'; control_logs.mkdir()
        execution = None
        try:
            row,stdout,stderr = bounded('boundary',['/usr/bin/sandbox-exec','-f',profile,self.boundary,canary,stage/'forbidden-write',stage/'work/input.txt'],stage/'work',environment,control_logs,wall=20,cpu=10)
            boundary = json.loads(stdout)
            assert row['exit_code'] == 0 and row['failure'] is None and not stderr and boundary['readable'] == boundary['shell_exec_denied'] == 1
            assert all(v in [1,13] for v in [boundary['outside_errno'],boundary['write_errno'],*boundary['network_errno']]) and len(boundary['network_errno']) == 4
            assert canary.read_text() == 'owned outside canary\n' and not (stage/'forbidden-write').exists()
            write(private/'qualified-before-client.json',dict(profile_sha256=sha(profile),boundary=boundary))
            if capability == 'bash':
                row,raw,errors = protocol(['/usr/bin/sandbox-exec','-f',profile,'/bin/bash','--noprofile','--norc','-c','printf ignored > /dev/null; printf "owned bash capability\\n"'],
                    stage/'work',environment,private/'owned-bash')
                assert row['exit_code'] == 0 and row['failure'] is None and not errors and raw == b'owned bash capability\n'
            execution,stdout,stderr = protocol(['/usr/bin/sandbox-exec','-f',profile,target,*argv],stage/'work',environment,private/'client',steps)
        finally:
            if server: server.close()
            if execution is not None:
                self.receipt['cases'].append(dict(name=name,label=label,execution=execution,profile_sha256=sha(profile),qualified_boundary=True))
        assert execution['failure'] is None and execution['exit_code'] == expected_exit_code and not stderr, name + ' bounded client failed; private records retained'
        frames = [json.loads(line) for line in stdout.splitlines()] if label == 'authored' or '--output-format' in argv else []
        if server: assert not server.errors
        requests = server.requests if server else []
        files = {}
        paths = list((stage/'work').rglob('*')); assert len(paths) <= 64 and not any(p.is_symlink() for p in paths)
        for path in paths:
            if path.is_file(): files[path.relative_to(stage/'work').as_posix()] = path.read_bytes()
        return dict(stage=stage, private=private, execution=execution, stdout=stdout, frames=frames,
                    requests=requests, files=files)

    def observe(self, result, *, json_output=True):
        normalizer = Normalize(str(result['stage']))
        value = dict(protocol=result['frames'] if json_output else result['stdout'].decode(),
            requests=[dict(path=r['path'],body=r['body']) for r in result['requests']], stderr='',exit=result['execution']['exit_code'],
            files={name:body.hex() for name,body in result['files'].items()})
        normalized = normalizer.value(value)
        folder = self.logs/result['private'].name; folder.mkdir()
        # Export only successful, parsed fixture responses. Unexpected raw output
        # and captured-source diagnostics always remain in private-records.
        write(folder/'observation.json',value); write(folder/'normalized.json',normalized)
        write(folder/'normalization.json',dict(fields=normalizer.audit,ids=normalizer.ids,devices=normalizer.devices))
        (folder/'client.stdout').write_bytes(result['stdout']); (folder/'client.stderr').write_bytes(b'')
        if result['requests']: shutil.copyfile(result['private']/'requests.json',folder/'requests.json')
        return normalized

    def compare(self, name, observations):
        for label in ['preserved','readable']:
            diff = differences(observations['original'],observations[label])
            row = dict(case=name,layout=label,equal=not diff,differences=diff[:50])
            self.receipt['differential_pairs'].append(row)
            assert not diff, name + ' protocol/API/file differential mismatch; records retained'
        print(json.dumps(dict(case=name,both_layouts_equal=True)),flush=True)

    def qualify_fixture(self):
        stage = self.output/'owned-runner-controls'; stage.mkdir()
        for part in ['work','home','tmp','fixtures','report']: (stage/part).mkdir()
        profile = stage/'profile.sb'; profile.write_text(self.profile(stage,self.runner,None))
        environment = dict(HOME=str(stage/'home'),TMPDIR=str(stage/'tmp'),PATH='/unavailable')
        owned_input = dict(file_path='owned.txt',content='fixture')
        steps = [dict(wait_json={'type':'control_request','request.subtype':'can_use_tool','request.tool_name':'Write'}),
            dict(send_permission_response=dict(behavior='allow',updatedInput=owned_input),expected_tool='Write',expected_input=owned_input),
            dict(wait_json={'type':'done','text':'α'}),dict(close_stdin=True)]
        runner_controls = []
        for name,target,argv,sequence,wall,expected in [
            ('fragmented-permission',self.runner,[],steps,20,None),
            ('bounded-flood',self.transport,['--flood'],None,5,'output limit'),
            ('descendant-held-pipe',self.runner,['--hold-descendant'],None,1,'wall timeout')]:
            row,stdout,stderr = protocol(['/usr/bin/sandbox-exec','-f',profile,target,*argv],stage/'work',environment,self.private/name,sequence,wall=wall)
            assert row['failure'] == expected and not stderr
            if expected is None: assert row['exit_code'] == 0 and row['completed_steps'] == len(steps)
            elif expected == 'output limit': assert len(stdout) == 262144
            runner_controls.append(dict(case=name,execution=row))
        self.receipt['runner_controls'] = runner_controls
        controls = check_sequence_fixture()
        result = self.execute('owned-sequence-fixture','authored',[self.probe,'@FIXTURE_PORT@'],spec=SPEC)
        assert result['frames'] == [dict(ordinal=i,events=controls[i-1]['events']) for i in [1,2,3]] + [dict(intl_number='12,345.5',intl_date='01/02/2020')]
        assert len(result['requests']) == 3
        self.receipt['fixture_controls'] = controls
        self.receipt['fixture_qualified'] = True

    def version(self):
        observations = {}
        for label in self.clients:
            result = self.execute('version-'+label,label,['--version'])
            assert result['stdout'] == b'2.1.296 (Claude Code)\n'
            observations[label] = self.observe(result,json_output=False)
        self.compare('version',observations)

    def tool_matrix(self, group):
        filename,digest = MATRICES[group]; path = ROOT.parent/'windows-recovery'/filename
        assert sha(path) == digest; matrix = json.loads(path.read_bytes()); shutil.copyfile(path,self.logs/filename)
        for case in matrix:
            observations = {}
            for label in self.clients:
                tools = {'search':'Grep,Glob','core':'Read,Edit'}[group]
                argv = arguments(tools,case['model'])
                if case.get('disallowed'): argv += ['--disallowedTools',case['disallowed']]
                result = self.execute(group+'-'+case['id']+'-'+label,label,[*argv,'--','fixture prompt'],
                    spec=dict(kind='tool_sequence_then_text',tools=case['tools'],text='core-tools-complete'),
                    work_input=case['input'],fixture_files=case.get('fixtures'),extra_env=case.get('env'))
                api = [r for r in result['requests'] if r['path'].split('?')[0] == '/v1/messages']
                terminal = [f for f in result['frames'] if f.get('type') == 'result']
                assert len(terminal) == 1 and terminal[0].get('is_error') is False and terminal[0].get('result') == 'core-tools-complete'
                assert len(api) == len(case['tools']) + 1
                results = []
                for ordinal,error in enumerate(case['tool_errors'],1):
                    matched = [c for m in api[ordinal]['body']['messages'] if isinstance(m.get('content'),list)
                        for c in m['content'] if c.get('type') == 'tool_result' and c.get('tool_use_id') == 'toolu_offline_fixture_'+str(ordinal)]
                    assert len(matched) == 1 and bool(matched[0].get('is_error',False)) == error
                    results.append(matched[0])
                content = json.dumps(results[-1].get('content'),ensure_ascii=False)
                assert all(s in content for s in case['last_result_contains']) and all(s not in content for s in case['last_result_excludes'])
                assert result['files'] == {'input.txt':case['expected'].encode()}, 'exact workspace bytes changed'
                observations[label] = self.observe(result)
            self.compare(group+'-'+case['id'],observations)

    def configuration(self):
        path = ROOT.parent/'windows-recovery/configuration-fixtures.json'; matrix=json.loads(path.read_bytes())
        shutil.copyfile(path,self.logs/path.name)
        for case in matrix['cases']:
            for variant in case['variants']:
                observations={}
                for label in self.clients:
                    inputs={}
                    def setup(stage,argv):
                        substitutions={'{{H}}':str(stage/'home'),'{{W}}':str(stage/'work'),'{{F}}':str(stage/'fixtures')}
                        def replace(text):
                            for key,value in substitutions.items(): text=text.replace(key,value)
                            return text
                        for name,content in matrix['fixtures'].items():
                            file=Path(replace(name));file.parent.mkdir(parents=True,exist_ok=True)
                            file.write_text('{ invalid' if case['id']=='C03' and name=='{{W}}/.claude/settings.local.json' else json.dumps(content)+'\n')
                            inputs[file]=sha(file)
                        return [replace(a) for a in argv]
                    steps=[*initialize(),dict(send_json=dict(type='control_request',request_id='settings-1',request=dict(subtype='get_settings'))),
                        dict(wait_json={'type':'control_response','response.request_id':'settings-1','response.subtype':'success'}),dict(close_stdin=True)]
                    result=self.execute('config-'+variant['id']+'-'+label,label,variant['argv'],setup=setup,steps=steps)
                    settings=next(f['response']['response'] for f in result['frames'] if matches(f,{'type':'control_response','response.request_id':'settings-1'}))
                    expected=MODELS[variant['id']]
                    assert settings['applied']['model']==expected and settings['effective']['model']==('claude-opus-5-5' if variant['id']=='cli' else expected)
                    if case['id']=='C02': assert not any(s.get('source') in ['userSettings','projectSettings','localSettings'] for s in settings.get('sources',[]))
                    if case['id']=='C03': assert settings.get('errors')
                    assert all(sha(p)==digest for p,digest in inputs.items())
                    observations[label]=self.observe(result)
                self.compare('config-'+variant['id'],observations)


def main():
    p=argparse.ArgumentParser();p.add_argument('--arch',choices=['arm64','x64'],required=True)
    for name in ['original','engine','build-receipt','output','logs']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--groups',default='version,search,core,config');a=p.parse_args()
    h=Harness(a.arch,a.original.resolve(),a.engine.resolve(),a.build_receipt.resolve(),a.output.resolve(),a.logs.resolve())
    try:
        h.qualify_fixture()
        for group in a.groups.split(','):
            if group in MATRICES:h.tool_matrix(group)
            elif group=='version':h.version()
            elif group=='config':h.configuration()
            elif group=='bash':
                from client_bash import accept
                accept(h,arguments)
            else:raise ValueError('unknown group')
        assert all(sha(path)==h.receipt['client_sha256'][label] for label,path in h.clients.items())
        h.receipt.update(status='selected_native_Mac_client_differential_cases_passed',inputs_preserved=True,groups=a.groups.split(','))
    except Exception as error:
        h.receipt.update(status='failed_private_records_retained',error_type=type(error).__name__);raise
    finally: write(h.logs/'client-acceptance.json',h.receipt)


if __name__=='__main__':main()
