from collections import Counter
import hashlib
import re

def parse(file):
    names={}; functions={}; edges=Counter()
    call=False;caller=callee=None; totals=None
    for line in file.read_text().splitlines():
        if line.startswith('events: '):events=line.split()[1:]
        elif line.startswith('positions: '):n=len(line.split())-1
        elif line.startswith('totals: '):totals=list(map(int,line.split()[1:]))
        elif line.startswith(('fn=','cfn=')):
            tag,val=line.split('=',1);m=re.fullmatch(r'\((\d+)\)(?: (.*))?',val)
            if m:
                if m[2] is not None:names[m[1]]=m[2]
                val=names[m[1]]
            if tag=='fn':caller=val
            else:callee=val
        elif line.startswith('calls='):
            edges[(caller,callee)]+=int(line.split('=',1)[1].split()[0]);call=True
        elif line and line[0] in '+-*0123456789':
            fields=line.split()
            if not call:
                count=list(map(int,fields[n:]))
                v=functions.setdefault(caller,[0]*len(events))
                for i,c in enumerate(count):v[i]+=c
            call=False
    assert events[:3]==['Ir','Dr','Dw'] and all(e in events for e in ('Bc','Bcm','Bi','Bim'))
    derived=[sum(row[i] for row in functions.values()) for i in range(len(events))]
    assert derived==totals+[0]*(len(events)-len(totals)),(derived,totals)
    return dict(events=events,totals=derived,
                functions=sorted(([k,*v] for k,v in functions.items() if any(v)),key=lambda item:-item[1]),
                calls=sorted(([c,f,x] for (c,f),x in edges.items() if x),key=lambda item:-item[2]),
                trace_sha256=hashlib.sha256(file.read_bytes()).hexdigest())
