"""Associate exclusive Callgrind instruction counts with the exact measured ELF."""
from collections import Counter,defaultdict
from pathlib import Path
from elftools.elf.elffile import ELFFile
import hashlib,json,re,shlex,shutil,subprocess as sp
TARGETS={'cs_decode_full_insn','X86_getInstruction','decodeInstructionFull','X86_Intel_printInst','X86_postprinter','readModRM','readOperands','X86_reg_access'}
UNITS={'cs.c','X86Disassembler.c','X86DisassemblerDecoder.c','X86IntelInstPrinter.c','X86Mapping.c'}
def digest(b):return hashlib.sha256(b).hexdigest()
def text_sections(path):
    with path.open('rb')as f:
        return {s.name:digest(s.data()) for s in ELFFile(f).iter_sections() if s['sh_flags']&4 and s.data_size}
def make(normal,lib,commands,root,link):
    diag=root/'line-debug';diag.mkdir();lib2=diag/lib.name;shutil.copyfile(lib,lib2);units={}
    for co in commands:
        name=Path(co['file']).name
        if name not in UNITS:continue
        argv=shlex.split(co['command']);base=Path(co['directory']);i=argv.index('-o')+1
        old=base/argv[i];new=diag/old.name;argv[i]=str(new)
        sp.run([*argv,'-gline-tables-only'],cwd=base,check=True)
        same=text_sections(old)==text_sections(new);units[name]=same
        if same:sp.run(['ar','r',lib2,new],check=True)
        new.unlink()
    debug=diag/'runner';sp.run([str(lib2)if a==lib else str(debug)if a==normal else a for a in link],check=True)
    a=text_sections(normal);b=text_sections(debug)
    # The normal executable is profiled even if debug metadata changes code generation.
    use=a==b
    with normal.open('rb')as f:
        sym=ELFFile(f).get_section_by_name('.symtab');symbols={}
        for n in TARGETS:
            rows=[s for s in sym.get_symbol_by_name(n) or [] if s['st_size'] and s['st_info']['type']=='STT_FUNC']
            if len(rows)==1:symbols[n]=(int(rows[0]['st_value']),int(rows[0]['st_size']))
    sites={}
    for name,(start,size) in symbols.items():
        dis=sp.check_output(['objdump','-d','--no-show-raw-insn','--disassemble='+name,normal],text=True)
        pcs={int(p,16):op.strip()for p,op in re.findall(r'^\s*([0-9a-f]+):\s+(\S[^\n]*)$',dis,re.M)if start<=int(p,16)<start+size}
        if not pcs:continue
        locations={}
        if use:
            query=''.join(hex(addr)+'\n'for addr in pcs)
            lines=sp.check_output(['addr2line','-e',debug],input=query,text=True).splitlines();assert len(lines)==len(pcs)
            for addr,label in zip(pcs,lines):
                file,_,line=label.rpartition(':');parts=Path(file).parts
                if 'capstone' in parts and parts[-1]!='??':file='/'.join(parts[parts.index('capstone')+1:])
                elif 'source' in parts:file='/'.join(parts[parts.index('source')+1:])
                else:file=Path(file).name
                n=line.split()[0]if line else '0'
                if n.isdecimal() and int(n)>0:locations[addr]=file+':'+n
        sites[name]={pc:(pc-start,op,locations.get(pc))for pc,op in pcs.items()}
    proof=dict(units=units,identical_executable_sections=use,measured_sections=a,with_lines_sections=b,profiled_binary=digest(normal.read_bytes()),
               functions={n:dict(address=symbols[n][0],length=symbols[n][1],instructions=len(s),with_source=sum(x[2]is not None for x in s.values()))for n,s in sites.items()})
    shutil.rmtree(diag)
    return sites,proof
def parse(profile,sites):
    pcmap={}
    for name,table in sites.items():
        for pc in table:
            assert pc not in pcmap
            pcmap[pc]=name
    fn='';obj='';edge=False
    by=defaultdict(Counter);contexts=defaultdict(Counter);outside=defaultdict(Counter)
    all_events=Counter();exe_events=Counter();under_names=defaultdict(Counter)
    with profile.open() as stream:
        for raw in stream:
            line=raw.strip()
            if line.startswith('cmd:'):exe=line.split()[1]
            elif line.startswith('positions:'):assert line.split()[1:]==['instr','line']
            elif line.startswith('events:'):events=line.split()[1:]
            elif line.startswith('totals:'):expected=Counter(dict(zip(events,map(int,line.split()[1:]))))
            elif line.startswith('ob='):obj=line[3:]
            elif line.startswith('fn='):
                fn=re.sub(r"'\d+$",'',line[3:])
                edge=False
            elif line.startswith(('calls=','jump=','jcnd=')):edge=True
            elif line.startswith('0x'):
                skip=edge;edge=False
                if skip:continue
                position,_,*counts=line.split()
                pc=int(position,16);values=dict(zip(events,map(int,counts)));all_events.update(values)
                if obj!=exe:continue
                exe_events.update(values);name=pcmap.get(pc)
                if fn in sites:under_names[fn].update(values)
                if name:
                    by[name,pc].update(values)
                    contexts[name][fn]+=values.get('Ir',0)
                elif fn in sites:outside[fn].update(values)
    assert all_events==expected,(all_events,expected)
    result={}
    for name in sites:
        rows=[(pc,v)for (fn,pc),v in by.items()if fn==name]
        if not rows:continue
        lines=defaultdict(Counter);total=Counter()
        for pc,v in rows:
            lines[sites[name][pc][2] or '(assembler)'].update(v)
            total.update(v)
        result[name]=dict(total=dict(total),lines=[(k,dict(v))for k,v in sorted(lines.items(),key=lambda it:-it[1]['Ir'])],
                         sites=[dict(offset=sites[name][pc][0],instruction=sites[name][pc][1],line=sites[name][pc][2],events=dict(v)) for pc,v in sorted(rows,key=lambda it:-it[1]['Ir'])[:24]],
                         logical_contexts=dict(contexts[name]))
        assert total['Ir']==sum(contexts[name].values())==sum(x['Ir']for x in lines.values())
    assert {'cs_decode_full_insn','X86_getInstruction','X86_Intel_printInst'}<=result.keys()
    for fn,v in under_names.items():
        assert v['Ir']==outside[fn]['Ir']+sum(z.get(fn,0) for z in contexts.values())
    mapped=sum(z['total']['Ir'] for z in result.values())
    assert 0<mapped<=exe_events['Ir']<=all_events['Ir']
    result['_accounting']=dict(all_events=dict(all_events),executable_events=dict(exe_events),target_instructions=mapped,
                               named_outside_targets={n:dict(v)for n,v in outside.items()},logical={n:dict(v)for n,v in under_names.items()})
    return result
