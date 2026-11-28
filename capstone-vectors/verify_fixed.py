import os,random,math,subprocess as sp

def run_test(w,image,cases,save,layouts):
    tags={'base':('base',0),'copy':('base',0),'candidate':('candidate',1),'repeat':('candidate',1),
          'fixed-base':('switch',0),'fixed-copy':('switch',0),'fixed-candidate':('switch',1),'fixed-repeat':('switch',1)}
    def take(case,tag,n,diagnostic=False):
        stage,choice=tags[tag];mode,blob,extent,bits=case
        if diagnostic:
            app=w/'count'
        else:
            image.select(stage);app=image.path
        result=sp.run(['setarch',os.uname().machine,'-R',app,'private',mode,str(n),blob,extent,bits],env=dict(os.environ,BENCH_SCAN=str(choice)),capture_output=True,check=True,text=True)
        fields=list(map(int,result.stdout.split()));assert len(fields)==6
        if diagnostic:
            line,=result.stderr.splitlines();a,b,c=line.split();assert (a,b)==('batch','calls')
            return fields[2:],int(c)
        return fields
    summary={};counts={}
    for name,case in cases.items():
        both=[take(case,t,1,True) for t in ('fixed-base','fixed-candidate')]
        assert both[0]==both[1] and (both[0][1]>0)==(case[0]=='0'),(name,both)
        counts[name]=dict(calls=both[0][1],record=both[0][0]);save('batch-calls',counts)
        n=max(1,math.ceil(22e6/take(case,'base',1)[0]))
        actual={t:take(case,t,n)[2:]for t in tags};assert all(a==actual['base'] for a in actual.values())
        order=list(tags);randomizer=random.Random('paired-batch-text/'+name);blocks=[]
        for i in range(35):
            randomizer.shuffle(order);block={t:[]for t in order}
            for t in order+order[::-1]:
                fields=take(case,t,n);assert fields[2:]==actual[t]
                block[t].append(fields[:2])
            blocks.append({t:[a+b for a,b in zip(*v)] for t,v in block.items()})
        summary[name]=dict(repeats=n,records=actual['base'],cycles=blocks);save('timings',summary)
    assert set(image.verified)=={'base','candidate','switch'}
