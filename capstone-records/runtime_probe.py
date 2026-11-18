from pathlib import Path
import json
import platform
import re
import shutil
import subprocess as sp

def cost_probe(binaries,cases,temporary,evidence,run):
    def save(name,v):(evidence/(name+'.json')).write_text(json.dumps(v,indent=2)+'\n')
    variants=['base','aa','iterator','leaf','candidate']
    control=json.loads((evidence/'launch-controls.json').read_text())
    assert control['aslr_disable_returncode']==0
    image=temporary/'same-image';maximum=control['fixed_size']
    payloads={v:binaries[v].read_bytes() for v in variants}
    padded={v:b+bytes(maximum-len(b)) for v,b in payloads.items()}
    def target(v):
        with image.open('r+b') as f:assert f.write(padded[v])==maximum
        assert image.stat().st_ino==control['inode'] and image.stat().st_size==maximum
        return image
    selected=[('arm-ls',2),('arm64-ls',0),('arm64-ls',2),('mips64el-ls',2)]
    case_by_name={x['name']:x for x in cases}
    arm=case_by_name['arm-ls'];symbol='_ZL3runR7SessionRKSt6vectorIhSaIhEEj'
    for v in ('base','iterator','leaf','candidate'):
        nm=sp.check_output(['nm','-n','--defined-only',binaries[v]],text=True)
        run_offset,=[int(line.split()[0],16) for line in nm.splitlines() if line.endswith(' '+symbol)]
        plt=sp.check_output(['objdump','-d','-j','.plt',binaries[v]],text=True)
        offset,=[int(x,16) for x in re.findall(r'^([0-9a-f]+) <memset@plt>:',plt,re.M)]
        binary=target(v)
        args=['setarch',platform.machine(),'-R','gdb','-q','-nx','-batch',
              '-ex','set $probe_run_link = '+hex(run_offset),'-ex','set $probe_memset_link = '+hex(offset),
              '-x',str(Path(__file__).with_name('probe.gdb')),'--args',str(binary),str(arm['selector']),'2',str(arm['path']),'1']
        try:
            result=sp.run(args,capture_output=True,text=True,timeout=45)
            text=result.stdout+result.stderr
            observations=[json.loads(line.split('MEMSET_PROBE ',1)[1]) for line in result.stdout.splitlines() if line.startswith('MEMSET_PROBE ')]
            record=dict(returncode=result.returncode,complete=len(observations)==8,observations=observations,run_link_offset=run_offset,memset_plt_link_offset=offset)
        except sp.TimeoutExpired as error:
            text=str(error);record=dict(complete=False,reason='debugger timeout',observations=[])
        (evidence/('gdb-fixed-'+v+'.log')).write_text(text);save('gdb-fixed-'+v,record)
    installed=sorted(Path('/usr/lib/linux-tools').glob('*/perf'))
    perf=str(installed[-1]) if installed else shutil.which('perf')
    if not perf:
        save('pmu',dict(supported=False,reason='perf not installed'));return
    (evidence/'perf-events.txt').write_bytes(sp.check_output([perf,'list']))
    setting=Path('/proc/sys/kernel/perf_event_paranoid');original=setting.read_text().strip()
    permission=sp.run(['sudo','-n','sysctl','-w','kernel.perf_event_paranoid=-1'],capture_output=True,text=True)
    audit=dict(original_setting=original,permission_returncode=permission.returncode,permission_stdout=permission.stdout,permission_stderr=permission.stderr,groups={})
    def parse(raw,events):
        counts={};running={}
        for line in raw.splitlines():
            columns=line.split(',')
            if len(columns)>=5 and columns[2] in events:
                if not columns[0].isdigit():return None
                counts[columns[2]]=int(columns[0]);running[columns[2]]=float(columns[4])
        if set(counts)!=set(events):return None
        return dict(counts=counts,running_percent=running)
    groups={'core':['cycles:u','instructions:u','branches:u','branch-misses:u'],
            'retired_fusion':['cycles:u','instructions:u','inst_retired.macro_fused:u','uops_retired.slots:u'],
            'issued':['cycles:u','instructions:u','uops_issued.any:u','idq.dsb_uops:u'],
            'transitions':['cycles:u','instructions:u','dsb2mite_switches.penalty_cycles:u','idq.mite_uops:u']}
    try:
        records=[]
        for group,events in groups.items():
            request='{'+','.join(events)+'}'
            probe=sp.run([perf,'stat','-x,','-e',request,'--','/bin/true'],capture_output=True,text=True)
            valid=parse(probe.stderr,events)
            audit['groups'][group]=dict(supported=probe.returncode==0 and valid is not None,returncode=probe.returncode,stderr=probe.stderr,parsed=valid)
            save('pmu',audit)
            if not audit['groups'][group]['supported']:continue
            keys=variants
            cycles=11 if group=='core' else 7
            for name,mode in selected:
                case=case_by_name[name];reference=None
                for cycle in range(cycles):
                    sequence=keys[cycle%len(keys):]+keys[:cycle%len(keys)]
                    for position,v in enumerate(sequence+sequence[::-1]):
                        binary=target(v);raw=temporary/'active.perf'
                        result=sp.run(['setarch',platform.machine(),'-R',perf,'stat','-x,','-e',request,'-o',str(raw),
                            '--',str(binary),str(case['selector']),str(mode),str(case['path']),'20'],capture_output=True,text=True)
                        assert result.returncode==0,(result.returncode,result.stderr)
                        output=json.loads(result.stdout);record=(output['first'],output['result'])
                        if reference is None:reference=record
                        else:assert reference==record
                        parsed=parse(raw.read_text(),events);assert parsed is not None,raw.read_text()
                        records.append(dict(group=group,case=name,mode=mode,cycle=cycle,position=position,variant=v,
                            counters=parsed,consumer=output,stderr=result.stderr,raw=raw.read_text()))
                save('pmu-samples',records)
        audit['supported']=audit['groups']['core']['supported']
        audit['samples']=len(records)
        # Resolve samples while the exact measured executable is still installed.
        # Sampling is diagnostic only and never contributes to throughput timing.
        raw=temporary/'active.perf.data'
        pre=sp.run([perf,'record','--no-buildid','--no-buildid-cache','-e','cycles:u','-c','1000003','-o',str(raw),'--','/bin/true'],capture_output=True,text=True)
        sampling=dict(preflight_returncode=pre.returncode,preflight_stderr=pre.stderr,records=[])
        if pre.returncode==0:
            case=case_by_name['arm64-ls'];reference=None
            for cycle in range(2):
                sequence=variants[cycle:]+variants[:cycle]
                for position,v in enumerate(sequence+sequence[::-1]):
                    binary=target(v);key='cycles-sampling-'+str(cycle)+'-'+str(position)+'-'+v
                    result=sp.run(['setarch',platform.machine(),'-R',perf,'record','--no-buildid','--no-buildid-cache',
                        '-e','cycles:u','-c','1000003','-o',str(raw),'--',str(binary),str(case['selector']),'0',str(case['path']),'400'],capture_output=True,text=True)
                    assert result.returncode==0,(result.returncode,result.stderr)
                    output=json.loads(result.stdout);value=(output['first'],output['result'])
                    if reference is None:reference=value
                    else:assert reference==value
                    report=sp.run([perf,'report','--stdio','--no-children','--show-nr-samples','--percent-limit','0','--sort','symbol',
                        '--no-demangle','-i',str(raw)],capture_output=True,text=True)
                    assert report.returncode==0,(report.returncode,report.stderr)
                    (evidence/(key+'.report.txt')).write_text(report.stdout)
                    import gzip
                    with gzip.open(evidence/(key+'.perf.data.gz'),'wb') as stream:stream.write(raw.read_bytes())
                    sampling['records'].append(dict(variant=v,cycle=cycle,position=position,case='arm64-ls',mode=0,consumer=output,
                        stderr=result.stderr,report_stderr=report.stderr,report=key+'.report.txt',data=key+'.perf.data.gz',
                        image_sha256=control['padded_sha256'][v]))
                    raw.unlink();save('cycle-sampling',sampling)
        save('cycle-sampling',sampling)
        raw.unlink(missing_ok=True)

    finally:
        if permission.returncode==0:
            restored=sp.run(['sudo','-n','sysctl','-w','kernel.perf_event_paranoid='+original],capture_output=True,text=True)
            audit.update(restore_returncode=restored.returncode,restore_stdout=restored.stdout,restore_stderr=restored.stderr)
        audit['final_setting']=setting.read_text().strip();audit['setting_restored']=audit['final_setting']==original
        save('pmu',audit);assert audit['setting_restored']
