"""Oracles retained from the accepted macOS/Linux authored matrix."""
import json
from contained_protocol import matches
from pathlib import Path
import shutil,hashlib
SID='00000000-0000-4000-8000-000000000001'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def lines(path):return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()] if path.exists() else []
def check_case(case,variant,run,frames,api,stage,report,before,out,malformed):
    terminal=[f for f in frames if f.get('type')=='result'];errors=[]
    if run['timeout'] or run['protocol_error'] or run['output_limit_reached']:errors.append('bounded runner failed')
    if malformed:errors.append('non-JSON stdout lines')
    missing_session=case['id']=='T02' and variant['id']=='resume_missing'
    if case['id'] not in ['J02','M02'] and not missing_session and len(terminal)!=1:errors.append('expected exactly one terminal result')
    if case['id']=='J03':
        # The original retries a 400 once without thinking.display.
        # This is a client compatibility fallback, not an SDK retry.
        fallback=False
        if len(api)==2:
            first=json.loads(json.dumps(api[0]['body']));second=api[1]['body']
            present='display' in first.get('thinking',{})
            first.get('thinking',{}).pop('display',None)
            fallback=present and first==second
        if not fallback or not terminal or terminal[0].get('is_error') is not True or terminal[0].get('api_error_status')!=400:errors.append('HTTP error or observed compatibility fallback not preserved')
    elif case['id']=='J02':
        if api or terminal or run['exit_code']==0:errors.append('malformed-input rejection differs from proposed oracle')
    elif not missing_session and case['id']!='T03' and terminal and terminal[0].get('is_error'):errors.append('unexpected error result')
    created=stage/'work/created.txt'
    if case['id'] in ['P01','P02','P03']:
        should_write=case['id'] in ['P01','P03'] and variant['id']=='allow'
        if created.exists()!=should_write:errors.append('Write side effect differs from permission oracle')
        if should_write and created.exists() and created.read_bytes()!=b'fixture-write\n':errors.append('created file content mismatch')
        if len(api)!=2:errors.append('expected tool call and following tool-result request')
    if case['id'] in ['H01','H02','H03']:
        hook_records=lines(stage/'helper-log/hooks.jsonl');(report/'hook-records.json').write_text(json.dumps(hook_records,indent=2)+'\n')
        events=[r.get('hook_event_name') for r in hook_records]
        if case['id']=='H01':
            required=['SessionStart','UserPromptSubmit','PreToolUse','PostToolUse','Stop']
            if any(e not in events for e in required):errors.append('missing lifecycle hook event')
            elif events.index('PreToolUse')>events.index('PostToolUse'):errors.append('tool hook causal order changed')
            if not any('fixture-input' in json.dumps(r['body'].get('messages',[])) for r in api):errors.append('Read result absent from next request')
        elif case['id']=='H03' and variant['id']=='invalid_text_continue':
            if not created.exists() or 'PreToolUse' not in events:errors.append('plain-text hook output no longer follows observed original continuation')
        elif created.exists() or 'PreToolUse' not in events or 'PostToolUse' in events:errors.append('hook did not block the Write')
        if len(api)!=2:errors.append('expected tool call and result after hook')
    if case['id'] in ['M01','M02']:
        mcp_records=lines(stage/'helper-log/mcp.jsonl');(report/'mcp-records.json').write_text(json.dumps(mcp_records,indent=2)+'\n')
        if case['id']=='M01':
            methods=[r.get('method') for r in mcp_records]
            if any(s not in methods for s in ['initialize','notifications/initialized','tools/list','tools/call']):errors.append('MCP lifecycle incomplete')
            if len(api)!=2 or not any('fixture-mcp:mcp-fixture-token' in json.dumps(r['body'].get('messages',[])) for r in api):errors.append('MCP tool result absent from next request')
        else:
            response=next((f for f in frames if matches(f,{'type':'control_response','response.request_id':'mcp-status-1'})),None)
            if api or run['exit_code']!=0 or not response:errors.append('MCP failure status or bounded shutdown missing')
            elif 'fixture' not in json.dumps(response) or '"connected"' in json.dumps(response):errors.append('MCP failed fixture reported as connected or omitted')
    if case['id']=='P04':
        seen=any('outside-fixture-token' in json.dumps(r['body'].get('messages',[])) for r in api)
        if seen != (variant['id']=='add_dir_allowed'):errors.append('outside-file permission oracle mismatch')
        if len(api)!=2:errors.append('expected Read and following tool-result request')
    if case['id']=='J01':
        if len(api)!=1 or not terminal or terminal[0].get('result')!='fixture-α-完成':errors.append('fragmented Unicode stream result mismatch')
    if case['id']=='T03':
        ack=next((f for f in frames if matches(f,{'type':'control_response','response.request_id':'interrupt-1','response.subtype':'success'})),None)
        if len(api)!=1 or not ack:errors.append('interrupt acknowledgment or request count mismatch')
        hold=json.loads((report/'hold.json').read_text())
        if not hold or not any(row.get('poll',0)>0 for row in hold):errors.append('fixture did not observe the interrupted connection close')
    if case['id'] in ['T01','T02']:
        transcript_files=[]
        for path in (stage/'home/.claude/projects').rglob('*.jsonl'):
            transcript_files.append({'path':str(path.relative_to(stage)), 'sha256':sha(path),'records':lines(path)})
        (report/'transcripts.json').write_text(json.dumps(transcript_files,indent=2)+'\n')
        if missing_session:
            if api or run['exit_code']==0 or any(not f.get('is_error') for f in terminal):errors.append('missing session started an API turn')
        else:
            if len(api)!=1 or not terminal or terminal[0].get('result')!=variant['stub']['text']:errors.append('session turn result mismatch')
        if case['id']=='T01':
            if variant['id'] in ['resume','fork']:
                history=json.dumps([r['body'].get('messages',[]) for r in api])
                if 'remember fixture-session-token' not in history or 'fixture-first-reply' not in history:errors.append('resumed API request lost prior conversation')
            if terminal:
                session=terminal[0].get('session_id')
                if (session==SID)!=(variant['id']!='fork'):errors.append('session identity mismatch')
                if not any(any(rec.get('sessionId')==session for rec in f['records']) for f in transcript_files):errors.append('transcript for result session missing')
            if variant['id']=='fork':
                old={r['path']:r['sha256'] for r in before['home'] if r.get('kind')=='file' and r['path'].endswith(SID+'.jsonl')}
                if not old or any(not (stage/'home'/path).exists() or sha(stage/'home'/path)!=digest for path,digest in old.items()):errors.append('fork mutated source session transcript')
            if variant['id']=='create':
                snapshot=out/'T01-create-snapshot';snapshot.mkdir(mode=0o700)
                for d in ['work','home','tmp']:shutil.copytree(stage/d,snapshot/d,symlinks=True)
        elif any(any(rec.get('sessionId')==SID for rec in f['records']) for f in transcript_files):errors.append('ephemeral session persisted a resumable transcript')
    return errors
