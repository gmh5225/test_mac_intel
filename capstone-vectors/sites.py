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
    symbols={};fn='';edge=False;by=defaultdict(Counter);summed=defaultdict(Counter)
    with profile.open()as f:
        for line in f:
            line=line.strip()
            if line.startswith('positions:'):positions=line.split()[1:];assert positions==['instr','line']
            elif line.startswith('events:'):events=line.split()[1:]
            elif line.startswith('fn='):
                fn=re.sub(r"'\d+$",'',line[3:]);edge=False
            elif line.startswith(('calls=','jump=','jcnd=')):edge=True
            elif line.startswith('0x'):
                skip=edge;edge=False
                if skip or fn not in sites:continue
                pc,_,*v=line.split();pc=int(pc,16)
                assert pc in sites[fn],(fn,hex(pc))
                events_at=dict(zip(events,map(int,v)))
                by[fn,pc].update(events_at);summed[fn].update(events_at)
    result={}
    for fn,total in summed.items():
        rows=[(pc,v)for (n,pc),v in by.items()if n==fn];lines=defaultdict(Counter)
        for pc,v in rows:lines[sites[fn][pc][2]or '(assembler)'].update(v)
        order=sorted(rows,key=lambda x:-x[1]['Ir'])
        result[fn]=dict(total=dict(total),lines=[(k,dict(v))for k,v in sorted(lines.items(),key=lambda x:-x[1]['Ir'])],
                        sites=[dict(offset=sites[fn][pc][0],instruction=sites[fn][pc][1],line=sites[fn][pc][2],events=dict(v))for pc,v in order[:24]])
        assert sum(x['Ir']for x in lines.values())==total['Ir']
    assert {'cs_decode_full_insn','X86_getInstruction','X86_Intel_printInst'}<=result.keys()
    return result
