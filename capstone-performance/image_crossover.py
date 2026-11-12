"""Cross the same two ELF images with two persistent executable inodes."""
from pathlib import Path
import ctypes
import hashlib
import json
import math
import os
import platform
import re
import shutil
import statistics
import struct
import subprocess
import sys

import layout_probe as layout
import run

WORK, OUT = run.WORK, run.EVIDENCE


def alloc_sections(data):
    table, = struct.unpack_from('<Q', data, 40)
    step, count, stridx = struct.unpack_from('<HHH', data, 58)
    assert step == 64 and data[:6] == b'\x7fELF\x02\x01'
    names_at, names_size = struct.unpack_from('<QQ', data, table + stridx * step + 24)
    names = data[names_at:names_at + names_size]
    rows = {}
    for i in range(count):
        name, kind, flags, addr, offset, size = struct.unpack_from('<IIQQQQ', data, table + i * step)
        if flags & 2 and size:
            key = names[name:names.index(b'\0', name)].decode()
            assert key not in rows
            rows[key] = (addr, size, offset, kind)
    return rows


def compare_images(images):
    tables = {k:alloc_sections(data) for k,data in images.items()}
    assert tables['base'].keys() == tables['new'].keys()
    mapped = json.loads((OUT / 'linked-text.json').read_text())
    x86 = mapped['padded-base-single']['text'][layout.MEMBER]
    assert (x86['address'], x86['size']) == tuple(mapped['padded-new-single']['text'][layout.MEMBER][k] for k in ('address','size'))
    diff = []
    for name, (address, size, offset, kind) in tables['base'].items():
        naddr, nsize, noff, nkind = tables['new'][name]
        same_layout = address == naddr and size == nsize and kind == nkind
        a = images['base'][offset:offset + size] if kind != 8 else b''
        b = images['new'][noff:noff + nsize] if nkind != 8 else b''
        if name == '.text':
            assert same_layout
            start, end = x86['address'] - address, x86['address'] - address + x86['size']
            assert a[:start] == b[:start] and a[end:] == b[end:] and a[start:end] != b[start:end]
        if a != b or not same_layout:
            diff.append(dict(name=name, base_address=address, new_address=naddr, base_size=size,
                             new_size=nsize, bytes_equal=(a == b), different_bytes=sum(c != d for c,d in zip(a,b))+abs(len(a)-len(b))))
    run.write('allocated-comparison.json', dict(sections=len(tables['base']), differing=diff,
        all_text_outside_x86_mapping_identical=True))


def private_offsets():
    src = WORK / 'placement_offsets.c'
    src.write_text('#include "MCInst.h"\n#include <stdio.h>\n#include <stddef.h>\n'
                   'int main(void) { printf("%zu %zu\\n", offsetof(MCInst,flat_insn), offsetof(cs_insn,detail)); return 0;}\n')
    import shlex
    db = json.loads((WORK / 'base-build/compile_commands.json').read_text())
    row = next(v for v in db if v['file'].endswith('/cs.c'))
    flags = [s for s in shlex.split(row['command']) if s.startswith('-D')]
    run.command(['clang',*flags,'-I',WORK/'base','-I',WORK/'base/include',src,'-o',WORK/'placement-offsets'],'placement-offsets')
    return [int(v) for v in subprocess.check_output([WORK/'placement-offsets'],text=True).split()]


def gdb_sample(slot, case, policy, offsets):
    first, second = ('$rdi','$rsi') if platform.machine() == 'x86_64' else ('$x0','$x1')
    commands = ['set pagination off', 'set confirm off', 'set disable-randomization '+('on' if policy=='fixed-aslr' else 'off'),
                'break *Mips_printer','run','set $rec=*(void**)((char*)'+first+'+'+str(offsets[0])+')',
                'set $detail=*(void**)((char*)$rec+'+str(offsets[1])+')',
                'printf "PLACEMENT %lx %lx %lx %lx\\n",(unsigned long)'+first+', (unsigned long)'+second+
                ', (unsigned long)$rec, (unsigned long)$detail']
    args = ['gdb','-q','-nx','-batch',*(item for cmd in commands for item in ('-ex',cmd)),
            '--args',slot,str(case['selector']),str(run.MODES[case['mode']]),case['path'],'1']
    out = subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=45)
    match = re.search(r'^PLACEMENT ([\da-f]+) ([\da-f]+) ([\da-f]+) ([\da-f]+)$',out.stdout,re.M)
    if not match:
        (OUT/'gdb-failure.log').write_text(out.stdout)
        raise ValueError('failed to capture private and public records')
    values = [int(k,16) for k in match.groups()]
    assert all(values)
    return dict(zip(('mcinst','sstream','public_insn','public_detail'),values))


def main():
    layout.build_controls()
    affinity = sorted(os.sched_getaffinity(0))
    os.sched_setaffinity(0,{affinity[0]})
    source = {s:(WORK/('padded-'+s+'-single')).read_bytes() for s in ('base','new')}
    compare_images(source)
    size = max(map(len,source.values()))
    data = {s:b.ljust(size,b'\0') for s,b in source.items()}
    digests = {s:hashlib.sha256(b).hexdigest() for s,b in data.items()}
    chunks = [(i,min(size,i+4096)) for i in range(0,size,4096) if data['base'][i:i+4096] != data['new'][i:i+4096]]
    assert 0 < len(chunks) < (size+4095)//4096
    slots = [WORK/'image-slot-a', WORK/'image-slot-b']
    for slot in slots:
        slot.write_bytes(data['base']); slot.chmod(0o755)
    inodes = [slot.stat().st_ino for slot in slots]; assert inodes[0] != inodes[1]
    assigned = ['base','base']
    def assign(labels):
        for i,(slot,side) in enumerate(zip(slots,labels)):
            if assigned[i] == side:
                continue
            with slot.open('r+b',buffering=0) as dst:
                for lo,hi in chunks:
                    dst.seek(lo); dst.write(data[side][lo:hi])
            assert slot.stat().st_ino == inodes[i] and run.sha(slot)==digests[side]
            assigned[i]=side
    test = subprocess.run(['setarch',platform.machine(),'-R','true'],capture_output=True,text=True)
    policies = ['ordinary']+(['fixed-aslr'] if test.returncode==0 else [])
    libc = ctypes.CDLL(None,use_errno=True)
    libc.personality.argtypes=[ctypes.c_ulong]; libc.personality.restype=ctypes.c_int
    def fixed_personality():
        old = libc.personality(0xffffffff)
        if old < 0 or libc.personality(old | 0x0040000) < 0:
            os._exit(90)
    def sample(case, slot, count, policy):
        args=['capstone-placement',str(case['selector']),str(run.MODES[case['mode']]),case['path'],str(count)]
        cp=subprocess.run(args,executable=slots[slot],preexec_fn=fixed_personality if policy=='fixed-aslr' else None,
                          capture_output=True,text=True,check=True)
        return json.loads(cp.stdout)
    cases=[c for c in json.loads((OUT/'cases.json').read_text()) if c['name'] in
           ('mips64el-ls','mips64el-cp','mips64el-sort','riscv64-ls','arc-libm') and c['mode'] in ('format','detail')]
    assert len(cases)==10
    offsets=private_offsets()
    focus=next(c for c in cases if c['name']=='mips64el-ls' and c['mode']=='detail')
    addresses=[]
    for sides in [(0,1),(1,0)]:
        assign([['base','new'][s] for s in sides])
        for i,side in enumerate(assigned):
            for policy in policies:
                for repeat in range(2):
                    addresses.append(dict(slot=i,side=side,policy=policy,repeat=repeat,
                                    **gdb_sample(slots[i],focus,policy,offsets)))
    run.write('observed-addresses.json',dict(scope='separate debugger runs at Mips_printer entry',offsets=offsets,addresses=addresses))
    counts=[]
    for c in cases:
        first=sample(c,0,1,'ordinary')
        count=max(1,round(70_000_000/max(1,first['cpu_ns'])))
        counts.append(count)
    run.write('crossover-plan.json',dict(source_hash=digests,inodes=inodes,changes_pages=len(chunks),
              one_slot_per_inode=True,affinity=affinity[0],policies=policies,aslr_probe=test.stderr,
              cycles=12,cases=cases,counts=counts))
    rows=[]
    # Each cycle times each image twice at each inode with reverse orders.
    with (OUT/'crossover-raw.jsonl').open('x') as log:
        for cycle in range(12):
            for phase in range(2):
                assign(['base','new'] if (cycle+phase)%2==0 else ['new','base'])
                for pos in range(len(cases)):
                    index=(pos+cycle*3+phase*5)%len(cases);c=cases[index]
                    for policy in policies[::(-1 if (cycle+phase)%2 else 1)]:
                        expected=None
                        for i in ([0,1,1,0] if (cycle+phase+pos)%2==0 else [1,0,0,1]):
                            value=sample(c,i,counts[index],policy)
                            signature=(value['first'],value['result'])
                            if expected is None:expected=signature
                            assert expected==signature
                            row=dict(case=c['name'],mode=c['mode'],cycle=cycle,phase=phase,policy=policy,
                                     side=assigned[i],slot=i,**{k:value[k] for k in ('cpu_ns','wall_ns')})
                            rows.append(row);log.write(json.dumps(row)+'\n')
                log.flush()
            print('image crossover cycle',cycle+1,flush=True)
    results=[]
    for c in cases:
        for policy in policies:
            trials=[]
            for cycle in range(12):
                group=[r for r in rows if (r['case'],r['mode'],r['cycle'],r['policy'])==(c['name'],c['mode'],cycle,policy)]
                t={(side,i):statistics.geometric_mean(r['cpu_ns'] for r in group if r['side']==side and r['slot']==i)
                   for side in ('base','new') for i in (0,1)}
                assert len(group)==8
                trials.append(dict(image_gain=math.sqrt(t['base',0]*t['base',1]/(t['new',0]*t['new',1])),
                              slot_effect=math.sqrt(t['base',0]*t['new',0]/(t['base',1]*t['new',1])),
                              slot_a_gain=t['base',0]/t['new',0],slot_b_gain=t['base',1]/t['new',1]))
            results.append(dict(case=c['name'],mode=c['mode'],policy=policy,trials=trials,
                           medians={k:statistics.median(v[k] for v in trials) for k in trials[0]}))
    run.write('crossover-summary.json',dict(complete=True,results=results))


if __name__=='__main__':
    if sys.argv[1:]==['cleanup']:
        run.cleanup()
    else:
        main()
