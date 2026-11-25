from pathlib import Path
import math
import os
import random
import subprocess

ROUTES = {
    'scan':('private',0), 'iced_scan':('iced',0),
    'text':('private',1), 'fast_text':('fast',1),
    'build_detail':('private',3), 'fast_build_detail':('fast',3),
    'operands':('private',4), 'fast_operands':('fast',4),
    'all_detail':('private',2), 'fast_all_detail':('fast',2),
    'public_text':('capstone',1), 'public_scan':('capstone',0),
}
def case(name,bits,image,fixture,extents,groups,measure,save):
    def command(tag,reps):
        engine,mode=ROUTES[tag]
        return [image,engine,str(mode),str(reps),fixture,extents,str(bits)]
    def visit(tag,reps):
        out=subprocess.check_output(['setarch',os.uname().machine,'-R',*command(tag,reps)],text=True)
        return list(map(int,out.split()))
    reps=max(1,math.ceil(18e6/visit('text',1)[0]))
    expected={tag:visit(tag,reps)[2:] for tag in ROUTES}
    assert all(len(sig)==4 for sig in expected.values())
    assert len({tuple(sig[:3])for sig in expected.values()})==1
    assert expected['public_scan']==expected['scan'] and expected['public_text']==expected['text'] and expected['text']==expected['build_detail']
    rows=dict(repeats=reps,signatures=expected,groups={})
    def series(label,blocks,read):
        rng=random.Random(f'{name}/{label}')
        order=list(ROUTES)
        result=[]
        for block in range(blocks):
            rng.shuffle(order);pair={}
            for tag in order+order[::-1]:
                values=read(tag)
                if tag not in pair:pair[tag]=values
                else:
                    assert pair[tag].keys()==values.keys()
                    for key,val in values.items():pair[tag][key]+=val
            result.append(pair)
        rows['groups'][label]=result;save('stage-'+name,rows)
    def uninstrumented(tag):
        cpu,wall,*sig=visit(tag,reps)
        assert sig==expected[tag]
        return {'cpu_ns':cpu,'wall_ns':wall}
    series('timing',21,uninstrumented)
    for group in ('work','branch','delivery','frontend_stalls','cache'):
        if group not in groups:continue
        def counters(tag):
            ok,counts,stdout,diag=measure(groups[group],command(tag,reps))
            assert ok and list(map(int,stdout.split()))[2:]==expected[tag],(name,group,tag,diag)
            return counts
        series(group,13,counters)
    return sorted(rows['groups'])
