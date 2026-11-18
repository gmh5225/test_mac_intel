from pathlib import Path
import gzip
import json
import platform
import subprocess as sp

def cost_probe(binaries, cases, temporary, evidence, run):
    def save(name, value):
        (evidence / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')
    if platform.machine() not in ('x86_64', 'amd64'):
        save('cost-protocol', dict(available=False, reason='No Callgrind counter run on this host architecture'))
        return
    selected = [('arm-ls',0), ('arm-ls',2), ('arm64-ls',0), ('mips64el-ls',2),
                ('putty-32-0.85',1), ('putty-64-0.85',1)]
    variants = ('base', 'scan')
    symbol = '_ZL3runR7SessionRKSt6vectorIhSaIhEEj'
    payloads = {v: binaries[v].read_bytes() for v in variants}
    control = json.loads((evidence / 'launch-controls.json').read_text())
    assert control['aslr_disable_returncode'] == 0
    maximum = control['fixed_size']
    padded = {v: b + bytes(maximum - len(b)) for v,b in payloads.items()}
    image = temporary / 'same-image'
    assert image.stat().st_ino == control['inode']
    records = []
    for case_name, mode in selected:
        case, = [x for x in cases if x['name'] == case_name]
        reference = None
        for variant in variants:
            with image.open('r+b') as out:
                assert out.write(padded[variant]) == maximum
            assert image.stat().st_ino == control['inode'] and image.stat().st_size == maximum
            key = 'cost-' + case_name + '-' + str(mode) + '-' + variant
            raw = temporary / 'active.callgrind'
            run(['setarch', platform.machine(), '-R', 'valgrind', '--tool=callgrind', '--demangle=no',
                 '--collect-atstart=no', '--toggle-collect=' + symbol, '--cache-sim=yes', '--branch-sim=yes',
                 '--dump-instr=yes', '--collect-jumps=yes', '--callgrind-out-file=' + str(raw),
                 image, str(case['selector']), str(mode), str(case['path']), '1'], key)
            lines = (evidence / (key + '.log')).read_text().splitlines()
            output = next(json.loads(line) for line in lines if line.startswith('{"selector":'))
            result = (output['first'], output['result'])
            assert output['repeats'] == 1 and output['first'] == output['result']
            if reference is None: reference = result
            else: assert reference == result
            text = raw.read_text()
            events = next(x[8:].split() for x in text.splitlines() if x.startswith('events: '))
            totals = list(map(int,next(x[8:].split() for x in text.splitlines() if x.startswith('totals: '))))
            assert len(events) == len(totals) and totals[0] > 0
            records.append(dict(case=case_name,mode=mode,variant=variant,events=dict(zip(events,totals)),
                                result=result,traversals=3,launch='same-file-fixed'))
            with gzip.open(evidence/(key+'.callgrind.gz'),'wb') as stream:stream.write(raw.read_bytes())
            raw.unlink();save('instruction-costs',records)
    assert len(records) == 12 and {(x['case'],x['mode'],x['variant']) for x in records} == {
        (c,m,v) for c,m in selected for v in variants}
    save('cost-protocol',dict(available=True,symbol=symbol,traversals=3,consumer_unchanged=True,
                             fixed_guest_argv=True,inode=control['inode'],fixed_size=maximum))
