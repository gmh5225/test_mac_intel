from contextlib import contextmanager
from pathlib import Path
import os
import random
import subprocess as sp

GROUPS={
    'work':['cycles:u','instructions:u'],
    'branch':['branches:u','branch-misses:u'],
    'delivery':['idq.dsb_uops:u','idq.mite_uops:u'],
    'frontend_stalls':['dsb2mite_switches.penalty_cycles:u','idq_uops_not_delivered.core:u'],
    'icache_stalls':['icache_data.stalls:u','icache_tag.stalls:u'],
    'cache':['L1-dcache-loads:u','L1-dcache-load-misses:u'],
}
@contextmanager
def hardware(source,work,save):
    sp.run(['clang','-std=c11','-O2','-fPIC','-shared',source/'window.c','-ldl','-o',work/'window.so'],check=True)
    sp.run(['clang','-std=c11','-O2','-fno-builtin-clock',source/'smoke.c','-o',work/'smoke'],check=True)
    paths=sorted(Path('/usr/lib/linux-tools').glob('*/perf'))
    tool=str(paths[-1])if paths else 'perf'
    setting=Path('/proc/sys/kernel/perf_event_paranoid')
    original=setting.read_text().strip()
    permission=sp.run(['sudo','-n','sysctl','-w','kernel.perf_event_paranoid=2'],capture_output=True,text=True) if int(original)>2 else None
    audit=dict(original=original,permission_returncode=permission.returncode if permission else None,perf=tool,groups={},cpu=sp.check_output(['lscpu'],text=True))
    def measure(events,command):
        inp,send=os.pipe();receive,ack=os.pipe()
        log=work/'current-stat.txt';log.unlink(missing_ok=True)
        try:
            args=[tool,'stat','--no-big-num','-x,','-o',log,'--delay=-1','--control',f'fd:{inp},{ack}','-e','{'+','.join(events)+'}','--',
                  'setarch',os.uname().machine,'-R','env','LD_PRELOAD='+str(work/'window.so'),f'ND_COUNTER_REQUEST={send}',f'ND_COUNTER_ACK={receive}',*command]
            result=sp.run(args,capture_output=True,text=True,pass_fds=(inp,send,receive,ack),timeout=35)
        finally:
            for fd in (inp,send,receive,ack):os.close(fd)
        raw=log.read_text() if log.exists() else ''
        counts={};running={}
        for line in raw.splitlines():
            cols=line.split(',')
            if len(cols)>=5 and cols[2]in events and cols[0].isdigit():
                counts[cols[2]]=int(cols[0]);running[cols[2]]=float(cols[4])
        usable=(result.returncode==0 and set(counts)==set(events) and min(running.values(),default=0)>=99 and result.stderr.count('nd-perf-window=2')==1)
        diagnostics=dict(rc=result.returncode,stderr=result.stderr[-1400:],perf=raw[-1400:],running=running)
        return usable,counts,result.stdout,diagnostics
    try:
        supported={}
        for group,events in GROUPS.items():
            ok,counts,stdout,diagnostics=measure(events,[work/'smoke','1'])
            audit['groups'][group]=dict(supported=ok,active=counts,diagnostics=diagnostics)
            if ok:supported[group]=events
        if 'work' in supported:
            ok,counts,_,diag=measure(GROUPS['work'],[work/'smoke','0'])
            hot=audit['groups']['work']['active']
            assert ok and hot['instructions:u']>1000000 and counts['instructions:u']<hot['instructions:u']/100,(counts,hot,diag)
            audit['inactive_window']=counts
        else:
            err=audit['groups']['work']['diagnostics']
            assert err['rc'] not in (81,82,83,84) and 'control did not acknowledge' not in err['stderr'],err
        save('hardware-capability',audit)
        yield supported,measure
    finally:
        if permission and permission.returncode==0:
            sp.run(['sudo','-n','sysctl','-w','kernel.perf_event_paranoid='+original],check=True,capture_output=True)
        audit['restored']=setting.read_text().strip()==original
        save('hardware-capability',audit)
        assert audit['restored']
