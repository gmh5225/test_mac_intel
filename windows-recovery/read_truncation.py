"""Authored small-cap Read cases. The existing fixture reports ten tokens."""
def tool(name, **data):return {'name':name,'input':data}
def read(**data):return tool('Read',file_path='/work/input.txt',**data)
def edit():return tool('Edit',file_path='/work/input.txt',old_string='TAIL_SENTINEL',new_string='TAIL_CHANGED')

def cases():
    multiline='target\n'+''.join('line%02d-abcdefghijk\n'%i for i in range(40))+'TAIL_SENTINEL\n'
    unicode_line='🐈'*41
    def row(name,text,tools,errors,*,model='claude-sonnet-5',expected=None,truncated=(),untruncated=(),kind='lines',contains=(),excludes=(),exact=None):
        return {'id':name,'input':text,'tools':tools,'tool_errors':errors,
            'expected':text if expected is None else expected,'last_result_contains':list(contains),'last_result_excludes':list(excludes),
            'model':model,'disallowed':None,'read_token_cap':8,'truncated_read_ordinals':list(truncated),
            'untruncated_read_ordinals':list(untruncated),'truncation_kind':kind,'exact_read_content':exact,
            'count_token_requests_min':1}
    return [
        row('R01-read-token-lines',multiline,[read()],[False],truncated=[1],contains=['target'],excludes=['TAIL_SENTINEL']),
        row('R02-partial-edit-legacy',multiline,[read(),edit()],[False,True],model='claude-sonnet-4-5',truncated=[1]),
        row('R03-partial-edit-current',multiline,[read(),edit()],[False,False],truncated=[1],expected=multiline.replace('TAIL_SENTINEL','TAIL_CHANGED')),
        row('R04-explicit-range-over-cap',multiline,[read(offset=1,limit=64)],[True],contains=['exceeds maximum allowed tokens']),
        row('R05-read-token-surrogate',unicode_line,[read()],[False],truncated=[1],kind='characters',exact='🐈'*27),
        row('R06-surrogate-edit-legacy',unicode_line,[read(),tool('Edit',file_path='/work/input.txt',old_string='🐈',new_string='🍂',replace_all=True)],
            [False,True],model='claude-sonnet-4-5',truncated=[1],kind='characters',exact='🐈'*27),
        row('R07-page-overwrites-partial',multiline,[read(),read(offset=1,limit=1),edit()],[False,False,False],
            model='claude-sonnet-4-5',truncated=[1],untruncated=[2],expected=multiline.replace('TAIL_SENTINEL','TAIL_CHANGED')),
    ]

def check(case,frames,requests):
    errors=[];reads={}
    for frame in frames:
        result=frame.get('tool_use_result')
        if frame.get('type')!='user' or not isinstance(result,dict) or result.get('type')!='text':continue
        for item in frame.get('message',{}).get('content',[]):
            if item.get('type')=='tool_result':reads[item['tool_use_id']]=result.get('file',{})
    for ordinal in case['truncated_read_ordinals']:
        file=reads.get('toolu_offline_fixture_'+str(ordinal),{})
        if file.get('truncatedByTokenCap') is not True:errors.append('missing true token-cap flag '+str(ordinal));continue
        content=file.get('content')
        if not isinstance(content,str) or not content or not case['input'].startswith(content) or len(content)>=len(case['input']):
            errors.append('truncated content is not a strict nonempty input prefix');continue
        try:content.encode('utf-8',errors='strict')
        except UnicodeEncodeError:errors.append('truncated content contains an unpaired surrogate')
        if case['exact_read_content'] is not None and content!=case['exact_read_content']:errors.append('Unicode boundary content mismatch')
        if case['truncation_kind']=='lines' and not file.get('numLines',0)<file.get('totalLines',0):errors.append('line truncation metadata mismatch')
    for ordinal in case['untruncated_read_ordinals']:
        file=reads.get('toolu_offline_fixture_'+str(ordinal),{})
        if not file or 'truncatedByTokenCap' in file:errors.append('explicit small page unexpectedly remains token-truncated')
    count=[r for r in requests if r['path'].split('?')[0]=='/v1/messages/count_tokens']
    if len(count)<case['count_token_requests_min']:errors.append('token count fixture was not exercised')
    return errors
