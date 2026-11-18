"""Keep guest launch arguments fixed while diagnosing libc memory operations."""
from pathlib import Path
import gzip
import hashlib
import json
import platform
import shutil
import subprocess as sp
from factorial import save

def cost_probe(binaries, cases, temporary, evidence, run):
    selected = [('arm-ls', 2), ('arm64-ls', 0), ('mips64el-ls', 2)]
    variants = ('base', 'iterator', 'leaf', 'candidate')
    symbol = '_ZL3runR7SessionRKSt6vectorIhSaIhEEj'
    payloads = {v: binaries[v].read_bytes() for v in variants}
    maximum = max(map(len, payloads.values()))
    padded = {v: b + bytes(maximum-len(b)) for v, b in payloads.items()}
    image = temporary / 'same-image'
    control = json.loads((evidence / 'launch-controls.json').read_text())
    assert image.stat().st_ino == control['inode'] and image.stat().st_size == maximum
    assert control['aslr_disable_returncode'] == 0
    inode = image.stat().st_ino
    def target(variant, launch):
        if launch == 'images':
            return binaries[variant]
        with image.open('r+b') as out:
            assert out.write(padded[variant]) == maximum
        assert image.stat().st_ino == inode and image.stat().st_size == maximum
        return image
    save(evidence, 'cost-launch-controls', dict(inode=inode, fixed_size=maximum,
        fixed_path=str(image), original_sha256={v: hashlib.sha256(b).hexdigest() for v,b in payloads.items()},
        raw_trace_path=str(temporary / 'active.callgrind'), fixed_guest_argv=True))
    for variant in variants:
        names = sp.check_output(['nm', '--defined-only', binaries[variant]], text=True)
        assert sum(line.endswith(' ' + symbol) for line in names.splitlines()) == 1
    records = []
    for case_name, mode in selected:
        case, = [x for x in cases if x['name'] == case_name]
        reference = None
        for launch in ('images', 'same-file-fixed'):
            for variant in variants:
                binary = target(variant, launch)
                key = 'cost-' + case_name + '-' + launch + '-' + variant
                raw = temporary / 'active.callgrind'
                fixed = ['setarch', platform.machine(), '-R'] if launch == 'same-file-fixed' else []
                run([*fixed, 'valgrind', '--tool=callgrind', '--demangle=no', '--collect-atstart=no',
                     '--toggle-collect=' + symbol, '--cache-sim=yes', '--branch-sim=yes',
                     '--dump-instr=yes', '--collect-jumps=yes', '--callgrind-out-file=' + str(raw),
                     binary, str(case['selector']), str(mode), str(case['path']), '1'], key)
                lines = (evidence / (key + '.log')).read_text().splitlines()
                output = next(json.loads(line) for line in lines if line.startswith('{"selector":'))
                result = (output['first'], output['result'])
                assert output['repeats'] == 1 and output['first'] == output['result']
                if reference is None:
                    reference = result
                else:
                    assert reference == result
                text = raw.read_text()
                events = next(x[8:].split() for x in text.splitlines() if x.startswith('events: '))
                totals = list(map(int, next(x[8:].split() for x in text.splitlines() if x.startswith('totals: '))))
                assert len(events) == len(totals) and totals[0] > 0
                records.append(dict(case=case_name, mode=mode, variant=variant, launch=launch,
                    events=dict(zip(events, totals)), result=result, traversals=3))
                with gzip.open(evidence / (key + '.callgrind.gz'), 'wb') as stream:
                    stream.write(raw.read_bytes())
                raw.unlink()
                save(evidence, 'instruction-costs', records)
    expected = {(c,m,l,v) for c,m in selected for l in ('images','same-file-fixed') for v in variants}
    assert len(records) == len(expected) and {(x['case'],x['mode'],x['launch'],x['variant']) for x in records} == expected
    save(evidence, 'cost-protocol', dict(symbol=symbol, consumer_unchanged=True, traversals=3,
        limitation='Simulated counts are independent of native implementation selection; both launch conditions are explicit.'))

    case, = [x for x in cases if x['name'] == 'arm-ls']
    script = Path(__file__).resolve().parent / 'probe.gdb'
    for launch in ('images', 'same-file-fixed'):
        for variant in variants:
            binary = target(variant, launch)
            fixed = ['setarch', platform.machine(), '-R'] if launch == 'same-file-fixed' else []
            result = sp.run([*fixed, 'gdb', '-q', '-nx', '-batch', '-x', str(script), '--args',
                str(binary), str(case['selector']), '2', str(case['path']), '1'],
                capture_output=True, text=True, timeout=60)
            key = 'gdb-' + launch + '-' + variant
            (evidence / (key + '.log')).write_text(result.stdout + result.stderr)
            observed = [json.loads(line.split('MEMSET_PROBE ',1)[1]) for line in result.stdout.splitlines() if line.startswith('MEMSET_PROBE ')]
            save(evidence, key, dict(returncode=result.returncode, observations=observed,
                 complete=len(observed)==8, scope='Separate native debugger run; the inferior is stopped after eight calls.'))

    installed = sorted(Path('/usr/lib/linux-tools').glob('*/perf'))
    perf = str(installed[-1]) if installed else shutil.which('perf')
    if not perf:
        save(evidence, 'pmu', dict(supported=False, reason='No perf executable installed'))
        return
    setting = Path('/proc/sys/kernel/perf_event_paranoid')
    original = setting.read_text().strip()
    permission = sp.run(['sudo','-n','sysctl','-w','kernel.perf_event_paranoid=-1'],capture_output=True,text=True)
    changed = permission.returncode == 0
    events = 'cycles:u,instructions:u,branches:u,branch-misses:u'
    audit = dict(original_setting=original, permission_returncode=permission.returncode,
                 permission_stdout=permission.stdout, permission_stderr=permission.stderr)
    try:
        probe = sp.run([perf,'stat','-x,','-e',events,'--','/bin/true'],capture_output=True,text=True)
        audit.update(supported=probe.returncode==0 and '<not supported>' not in probe.stderr,
                     probe_returncode=probe.returncode, probe_stdout=probe.stdout, probe_stderr=probe.stderr)
        if audit['supported']:
            for variant in variants:
                binary = target(variant,'same-file-fixed')
                key='pmu-fixed-'+variant
                result=sp.run(['setarch',platform.machine(),'-R',perf,'stat','-x,','-e',events,
                    '-o',str(evidence/(key+'.txt')),'--',str(binary),str(case['selector']),'2',str(case['path']),'20'],
                    capture_output=True,text=True)
                save(evidence,key,dict(returncode=result.returncode,stdout=result.stdout,stderr=result.stderr))
    finally:
        if changed:
            restored=sp.run(['sudo','-n','sysctl','-w','kernel.perf_event_paranoid='+original],capture_output=True,text=True)
            audit.update(restore_returncode=restored.returncode,restore_stdout=restored.stdout,restore_stderr=restored.stderr)
        audit['final_setting']=setting.read_text().strip()
        audit['setting_restored']=audit['final_setting']==original
        save(evidence,'pmu',audit)
        assert audit['setting_restored'],audit
