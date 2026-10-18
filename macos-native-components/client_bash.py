"""Actual Bash calls under the independently qualified inherited Seatbelt policy."""
import json
import shlex


def accept(h, arguments):
    cases=[
        dict(id='B01-streams-unicode',command="printf 'stdout α 🐈\\n'; printf 'stderr fixture\\n' >&2",error=False,contains=['stdout α 🐈','stderr fixture']),
        dict(id='B02-exit-37',command="printf 'before exit\\n'; exit 37",error=True,contains=['before exit','Exit code 37']),
        dict(id='B03-pipeline-write',command="printf 'pipeline fixture\\n' | /bin/cat > result.txt; /bin/cat result.txt",error=False,contains=['pipeline fixture'],extra_file='pipeline fixture\n'),
        dict(id='B04-denied-write',command="printf forbidden > ../forbidden-write",error=True,contains=['Operation not permitted']),
        dict(id='B05-denied-read',command="/bin/cat ../outside-canary",error=True,contains=['Operation not permitted']),
        dict(id='B06-fd3-closed',command="if [ -e /dev/fd/3 ]; then printf 'descriptor leaked\\n'; exit 77; fi; printf 'descriptor closed\\n'",error=False,contains=['descriptor closed']),
        dict(id='B07-inherited-policy',command=shlex.quote(str(h.boundary))+' ../outside-canary ../forbidden-write input.txt',error=False,
            contains=['"outside_errno":1','"write_errno":1','"network_errno":[1,1,1,1]','"shell_exec_denied":1'])]
    (h.logs/'bash-case-matrix.json').write_text(json.dumps(cases,ensure_ascii=False,indent=2)+'\n')
    for case in cases:
        observations={}
        for label in h.clients:
            spec=dict(kind='tool_then_text',tool=dict(name='Bash',input=dict(command=case['command'],description='Run the owned offline fixture')),text='bash-fixture-complete')
            argv=[*arguments('Bash'),'--settings',json.dumps(dict(sandbox=dict(enabled=False)),separators=(',',':')),'--','fixture prompt']
            result=h.execute('bash-'+case['id']+'-'+label,label,argv,spec=spec,capability='bash')
            api=[r for r in result['requests'] if r['path'].split('?')[0]=='/v1/messages']
            terminal=[f for f in result['frames'] if f.get('type')=='result']
            assert len(api)==2 and len(terminal)==1 and terminal[0].get('is_error') is False and terminal[0]['result']=='bash-fixture-complete'
            matched=[c for message in api[1]['body']['messages'] if isinstance(message.get('content'),list)
                for c in message['content'] if c.get('type')=='tool_result' and c.get('tool_use_id')=='toolu_offline_fixture_1']
            assert len(matched)==1 and bool(matched[0].get('is_error',False))==case['error']
            body=matched[0].get('content')
            assert isinstance(body,str) or isinstance(body,list) and all(row.get('type')=='text' and isinstance(row.get('text'),str) for row in body)
            content=body if isinstance(body,str) else '\n'.join(row['text'] for row in body)
            assert all(value in content for value in case['contains'])
            if case['id']=='B07-inherited-policy':
                assert json.loads(content)==dict(outside_errno=1,write_errno=1,readable=1,network_errno=[1,1,1,1],shell_exec_denied=1)
            expected={'input.txt':b'fixture input\n'}
            if 'extra_file' in case:expected['result.txt']=case['extra_file'].encode()
            assert result['files']==expected and not (result['stage']/'forbidden-write').exists()
            assert (result['stage']/'outside-canary').read_bytes()==b'owned outside canary\n'
            observations[label]=h.observe(result)
        h.compare('bash-'+case['id'],observations)
    h.receipt['Bash_scope']='Seven actual Bash cases with the qualified inherited Seatbelt profile. Product nested sandbox is disabled explicitly and is not accepted by these cases.'
