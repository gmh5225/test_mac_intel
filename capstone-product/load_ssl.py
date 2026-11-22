from pathlib import Path
import hashlib,json
import frozen_ssl
def prepare(source,work,evidence,command):
    data,=frozen_ssl.prepare(work)
    name,bits,path,spans,meta=data
    assert name=='libssl3t64-i386' and bits==32 and len(spans)==12771 and sum(n for _,n,_ in spans)==2420472
    intervals=work/'openssl-i386-functions.txt'
    intervals.write_text(''.join('%d %d %d\n'%span for span in spans))
    (evidence/'openssl-corpus.json').write_text(json.dumps(dict(metadata=meta,functions=len(spans),bytes=2420472,selection='All frozen mutually decodable function extents',intervals_sha256=hashlib.sha256(intervals.read_bytes()).hexdigest()),indent=2)+'\n')
    return dict(name=name,selector=bits,path=str(path),intervals=str(intervals),text_sha256=meta['text_sha256'])
