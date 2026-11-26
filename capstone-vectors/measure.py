from pathlib import Path
import json,shutil,subprocess as sp,sys
r=Path(__file__).resolve().parent;src=r.parent/'source';out=r.parent/'evidence';out.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text())
def git(*a):return sp.check_output(['git','-C',src,*a],text=True).strip()
def save(k,v):(out/(k+'.json')).write_text(json.dumps(v,indent=2)+'\\n')
q=rd(r/'source.json');result={};cleanup={}
try:
    for tag in ('base','prefix','outlined'):
        git('restore','--source','HEAD','--staged','--worktree','--','.')
        if tag!='base':git('apply','--index',str(r/(tag+'.patch')))
        assert git('write-tree')==q[tag]['tree']
        sp.run([sys.executable,'-B',r/'counts.py',tag],check=True)
        f=out/tag;result[tag]=dict(source=q[tag],host=rd(f/'complete.json'),observations=rd(f/'observations.json'))
        cleanup[tag]=rd(f/'cleanup.json')
    save('complete',dict(complete=True,variants=result))
finally:
    for tag in ('base','prefix','outlined'):
        f=out/tag/'cleanup.json'
        if f.exists():cleanup[tag]=rd(f)
    save('cleanup',dict(removed=bool(cleanup) and all(z['removed']for z in cleanup.values()),bytes=sum(z['bytes']for z in cleanup.values()),variants=cleanup))
