"""Assign instructions retired inside the inlined iced adapter to the actual DWARF frame."""
from collections import Counter
from pathlib import Path
import hashlib,re,subprocess as sp
from elftools.elf.elffile import ELFFile

def inspect(binary,debug):
    with binary.open('rb') as stream:
        elf=ELFFile(stream)
        fn,=elf.get_section_by_name('.symtab').get_symbol_by_name('iced_run')
        sec=elf.get_section(fn['st_shndx']);start=fn['st_value'];size=fn['st_size']
        bias=min(s['p_vaddr']-s['p_offset'] for s in elf.iter_segments() if s['p_type']=='PT_LOAD')
        off=start-sec['sh_addr'];code=sec.data()[off:off+size]
    info=dict(address=start,size=size,load_bias=bias,body_sha256=hashlib.sha256(code).hexdigest())
    frames={}
    if debug:
        dump=sp.check_output(['objdump','-d','--no-show-raw-insn','--start-address='+hex(start),'--stop-address='+hex(start+size),binary],text=True)
        pcs=[int(v,16) for v in re.findall(r'^\s*([0-9a-f]+):\s+\S+',dump,re.M)]
        for first in range(0,len(pcs),800):
            subset=pcs[first:first+800]
            output=sp.check_output(['addr2line','-a','-f','-i','-C','-e',binary,*map(hex,subset)],text=True)
            blocks=re.split(r'^0x([0-9a-f]+)\n',output,flags=re.M)
            for addr,group in zip(blocks[1::2],blocks[2::2]):
                lines=group.rstrip().splitlines()
                stack=list(zip(lines[::2],lines[1::2]))
                levels=[]
                for fun,loc in stack:
                    loc=loc.split(' (discriminator')[0]
                    if '/iced-x86/src/' in loc:
                        loc=loc.split('/iced-x86/src/')[-1]
                        if loc.startswith('formatter/'):owner='formatter'
                        elif loc.startswith(('decoder/','decoder.rs:')):owner='decoder'
                        elif loc.startswith(('info/','info.rs:')):owner='info'
                        else:owner='instruction/accessors'
                    elif re.search(r'(^|/)iced\.rs:',loc):owner='benchmark';loc='iced.rs:'+loc.rsplit(':',1)[-1]
                    else:owner='runtime/other';loc=Path(loc).name
                    levels.append((owner,loc,fun))
                # Attribute embedded helpers to the nearest owning formatter, decoder or info frame.
                take=next((z for z in levels if z[0] in ('formatter','decoder','info')),None)
                if take is None:take=next((z for z in levels if z[0]!='runtime/other'),levels[0])
                frames[int(addr,16)]=take
        assert all(pc in frames for pc in pcs) and frames and any(v[0]=='formatter' for v in frames.values()),Counter(v[0]for v in frames.values())
    return info,frames

def profile(work,invoke,program,arguments,info,frames):
    native=list(map(int,sp.check_output([*invoke,program,*arguments],text=True).split()))[2:]
    dest=work/'inline.profile'
    args=[*invoke,'valgrind','--tool=callgrind','--instr-atstart=no','--compress-strings=no','--compress-pos=no',
          '--dump-instr=yes','--dump-line=no','--callgrind-out-file='+str(dest),program,*arguments]
    job=sp.run(args,capture_output=True,text=True)
    if job.returncode:raise RuntimeError(job.stderr[-3000:])
    assert native==list(map(int,job.stdout.split()))[2:]
    dest.unlink();profile=dest.with_name(dest.name+'.1')
    whole=0;spans=0;name='';target='';edge=False;total=None;ex=Counter();sources=Counter();funcs=Counter();owners=Counter()
    obj='';physical=0;producer=Counter();outside=Counter()
    low=info['address'];high=low+info['size']
    with profile.open() as inp:
        for raw in inp:
            line=raw.rstrip()
            if line.startswith('positions:'):positions=line.split()[1:]
            elif line.startswith('events:'):events=line.split()[1:]
            elif line.startswith('ob='):obj=line[3:]
            elif line.startswith('fn='):name=line[3:].split("'")[0]
            elif line.startswith('cfn='):target=line[4:].split("'")[0]
            elif line.startswith('calls='):
                if target=='observed_span':spans+=int(line.split()[0][6:])
                edge=True
            elif line.startswith(('jump=','jcnd=')):edge=True
            elif line.startswith('totals:'):total=int(line.split()[1+events.index('Ir')])
            elif line and line[0].isdigit():
                if edge:edge=False;continue
                fields=line.split();idx=len(positions)+events.index('Ir');ir=int(fields[idx]) if idx<len(fields) else 0
                if ir:
                    whole+=ir;ex[name]+=ir
                    rawpc=int(fields[positions.index('instr')],0)
                    # Callgrind may name an inlined frame from another physical address.
                    # Attribute by the actual executable section and address instead.
                    if obj==str(program) or Path(obj).name==program.name:
                        pc=rawpc if low<=rawpc<high else rawpc+info['load_bias']
                        if low<=pc<high:
                            physical+=ir;producer[name]+=ir
                            if frames:
                                stage,site,func=frames[pc]
                                owners[stage]+=ir;sources[site]+=ir;funcs[func]+=ir
                        elif name=='iced_run':outside[hex(rawpc)]+=ir
    profile.unlink()
    assert total==whole>0 and physical>0 and sum(producer.values())==physical and (not frames or sum(owners.values())==physical),(whole,physical,ex.most_common(6),low,high,obj)
    assert spans==sum(bool(x.strip())for x in Path(arguments[-2]).read_text().splitlines()),(spans,arguments)
    return dict(records=native,spans=spans,ir=whole,inside=physical,callgrind_named=ex['iced_run'],physical_names=producer.most_common(15),named_outside=outside.most_common(12),owners=owners,lines=sources.most_common(32),functions=funcs.most_common(14),top=ex.most_common(15))
