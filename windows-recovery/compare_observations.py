from pathlib import Path
import argparse,copy,json,re
SID='00000000-0000-4000-8000-000000000001';UID='00000000-0000-4000-8000-000000000011'
TIMING={'duration_ms','duration_api_ms','ttft_stream_ms','ttft_ms','first_content_frame_ms','time_to_request_ms'}
def differences(a,b,path=''):
    if type(a)!=type(b):return [{'path':path,'original':a,'candidate':b}]
    if isinstance(a,dict):
        out=[]
        for k in sorted(a.keys()|b.keys()):
            if k not in a or k not in b:
                out.append({'path':path+'/'+k,'original_present':k in a,'candidate_present':k in b})
            else:out.extend(differences(a[k],b[k],path+'/'+k))
        return out
    if isinstance(a,list):
        out=[] if len(a)==len(b) else [{'path':path,'original_length':len(a),'candidate_length':len(b)}]
        return out+[d for i,(x,y) in enumerate(zip(a,b)) for d in differences(x,y,path+'/'+str(i))]
    return [] if a==b else [{'path':path,'original':a,'candidate':b}]
class Normalize:
    def __init__(self,stage):self.stage=stage;self.ids={};self.devices={};self.pipes={};self.audit=[]
    def value(self,x,path=''):
        if isinstance(x,dict):
            result={}
            for k,v in x.items():
                p=path+'/'+k
                if k=='messaging_socket_path':
                    assert isinstance(v,str) and re.fullmatch(r'\\\\\.\\pipe\\LOCAL\\cc-msg-[0-9a-f]{32}',v),(p,v)
                    self.pipes.setdefault(v,r'\\.\pipe\LOCAL\cc-msg-$PIPE'+str(len(self.pipes)))
                    self.audit.append({'path':p,'value':v,'kind':'generated_messaging_pipe'});result[k]=self.pipes[v]
                elif k in TIMING:
                    assert isinstance(v,(float,int)) and v>=0,(p,v)
                    self.audit.append({'path':p,'value':v,'kind':'elapsed_time'});result[k]='$ELAPSED'
                elif k=='timestamp' and isinstance(v,str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z',v):
                    self.audit.append({'path':p,'value':v,'kind':'event_clock'});result[k]='$TIMESTAMP'
                elif k=='request_sent_wall_ms':
                    assert type(v)is int and v>1000000000000
                    self.audit.append({'path':p,'value':v,'kind':'request_wall_clock'});result[k]='$WALL_CLOCK'
                elif p.endswith('/response/response/pid'):
                    assert type(v)is int and v>0;self.audit.append({'path':p,'value':v,'kind':'process_id'});result[k]='$PID'
                elif k=='user_id' and path.endswith('/metadata'):
                    ident=json.loads(v);device=ident.get('device_id');assert re.fullmatch('[0-9a-f]{64}',device)
                    self.devices.setdefault(device,'$DEVICE'+str(len(self.devices)));ident['device_id']=self.devices[device]
                    result[k]=json.dumps(self.value(ident,p),sort_keys=True,separators=(',',':'))
                else:result[k]=self.value(v,p)
            return result
        if isinstance(x,list):return [self.value(v,path+'/'+str(i)) for i,v in enumerate(x)]
        if isinstance(x,str):
            if x in self.pipes:return self.pipes[x]
            x=x.replace(self.stage,'$STAGE').replace(self.stage.replace('\\','/'),'$STAGE').replace(re.sub('[^a-zA-Z0-9]','-',self.stage),'$ENCODED_STAGE')
            if x not in [SID,UID] and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',x):
                self.ids.setdefault(x,'$UUID'+str(len(self.ids)));return self.ids[x]
        return x
