"""Real built-in Grep/Glob after rebuilding the source-native engine prefix."""
from pathlib import Path
import hashlib,json,shutil
from compare_bash import Normalize,differences

MATRIX = Path(__file__).resolve().parent.parent / "windows-recovery/search-tool-cases.json"
MATRIX_SHA = "34e694c01daae7d1fbc9f053c96b48e588d07c381ee514ae49b02907e981fa7e"

def accept_native_search(execute, original, clients, logs):
    assert hashlib.sha256(MATRIX.read_bytes()).hexdigest() == MATRIX_SHA
    matrix = json.loads(MATRIX.read_bytes()); assert len(matrix) == 13
    shutil.copyfile(MATRIX,logs/'native-search-case-matrix.json')
    shutil.copyfile(Path(__file__),logs/'source/native_search_acceptance.py')
    receipt = dict(status='started',cases=[],differential_pairs=[],matrix_sha256=MATRIX_SHA,
        managed_search_launcher_used=False,external_rg_on_path=False,original_descriptor_provider_preserved=True,
        goal_complete=False)
    try:
        for case in matrix:
            observations = {}
            for label in ['original','preserved','readable']:
                name = 'native-search-'+label+'-'+case['id']
                client = {'original': original} if label == 'original' else {'client-'+label:clients[label]}
                executable = '/runtime/original' if label == 'original' else '/runtime/client-'+label
                spec = dict(kind='tool_sequence_then_text',tools=case['tools'],text='core-tools-complete')
                argv = ['-p','--output-format','stream-json','--verbose','--strict-mcp-config','--mcp-config','{"mcpServers":{}}',
                    '--no-chrome','--disable-slash-commands','--permission-mode','manual','--permission-prompts','none',
                    '--system-prompt','Offline fixture. Use only supplied fixture data.','--setting-sources','',
                    '--tools','Grep,Glob','--allowedTools','Grep,Glob','--model',case['model'],
                    '--session-id','00000000-0000-4000-8000-000000000001',
                    '--debug-file','/report/client-debug.txt','--','fixture prompt']
                extra = {}
                for key,value in case.get('env',{}).items():
                    assert key=='RIPGREP_CONFIG_PATH' and value.startswith('/fixtures/')
                    extra[key]='/home/test/'+value[len('/fixtures/'):]
                execution,state = execute(name,[executable],spec,client=client,arguments=argv,
                    work_input=case['input'],fixture_files=case.get('fixtures',{}),extra_env=extra)
                assert execution['exit_code']==0 and not execution['stderr'],execution
                frames = [json.loads(line) for line in execution['stdout'].splitlines()]
                requests_file=state/'report/requests.jsonl'
                requests=[json.loads(line) for line in requests_file.read_text().splitlines()]
                api=[row for row in requests if row['path'].split('?')[0]=='/v1/messages']
                terminal=[f for f in frames if f.get('type')=='result']
                assert len(terminal)==1 and not terminal[0].get('is_error') and terminal[0].get('result')=='core-tools-complete'
                assert len(api)==len(case['tools'])+1
                results=[]
                for ordinal,error in enumerate(case['tool_errors'],1):
                    matched=[c for m in api[ordinal]['body']['messages'] if isinstance(m.get('content'),list)
                        for c in m['content'] if c.get('type')=='tool_result' and c.get('tool_use_id')=='toolu_offline_fixture_'+str(ordinal)]
                    assert len(matched)==1 and bool(matched[0].get('is_error',False))==error
                    results.append(matched[0])
                content=json.dumps(results[-1].get('content'),ensure_ascii=False)
                # Record the actual result before an oracle can fail. Raw API
                # requests, streams and the client debug log remain untouched.
                (logs/name/'tool-results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n')
                assert all(s in content for s in case['last_result_contains']), (case['id'],label,results)
                assert all(s not in content for s in case['last_result_excludes']), (case['id'],label,results)
                paths=list((state/'work').rglob('*'));assert len(paths)<=32 and not any(p.is_symlink() for p in paths)
                files={p.relative_to(state/'work').as_posix():p.read_bytes() for p in paths if p.is_file()}
                assert files=={'input.txt':case['expected'].encode()}
                normalizer=Normalize('/home/test')
                observed=normalizer.value(dict(protocol=frames,requests=[r['body'] for r in requests],
                    stderr=execution['stderr'],exit=execution['exit_code']))
                observations[label]=observed
                folder=logs/name
                (folder/'normalized.json').write_text(json.dumps(observed,ensure_ascii=False,indent=2)+'\n')
                (folder/'workspace-files.json').write_text(json.dumps({k:v.hex() for k,v in files.items()},indent=2)+'\n')
                row=dict(case=case['id'],label=label,oracles_pass=True,tool_results=results,
                    files={k:hashlib.sha256(v).hexdigest() for k,v in files.items()},normalization=normalizer.audit)
                receipt['cases'].append(row)
                print(json.dumps(dict(native_search_case=case['id'],label=label,oracles='pass')),flush=True)
            for label in ['preserved','readable']:
                diff=differences(observations['original'],observations[label])
                receipt['differential_pairs'].append(dict(case=case['id'],layout=label,equal=not diff,differences=diff[:50]))
                assert not diff,'Built-in search differential mismatch; preserve the full records'
        assert len(receipt['differential_pairs'])==26
        receipt.update(status='thirteen_builtin_search_cases_match_both_layouts',
            scope='Actual native rg dispatch from both rebuilt client layouts with original provider source and no external rg on PATH. Ordered protocol/API, stderr/exits and exact workspace bytes; bounded cases only.')
        return receipt
    finally:
        (logs/'native-search-acceptance.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n')
