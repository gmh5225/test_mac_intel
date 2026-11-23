import re,subprocess as sp
def layout(path,objdump='objdump',nm='nm'):
    sections={}
    for line in sp.check_output([objdump,'-h',path],text=True).splitlines():
        match=re.match(r'^\s*\d+\s+(\.\S+)\s+([\da-f]+)\s+([\da-f]+)\s+[\da-f]+\s+([\da-f]+)',line)
        if match:
            s,n,va,fp=match.groups();sections[s]=[int(va,16),int(n,16),int(fp,16)]
    symbols={}
    for line in sp.check_output([nm,'-n','-S','--defined-only',path],text=True).splitlines():
        v=line.split()
        if len(v)==4 and v[3] in ('matchAArch64AliasPatterns','matchMipsAliasPatterns','AArch64_alias_blocks','Mips_alias_blocks','cs_disasm_iter','AArch64_getInstruction','Mips_getInstruction'):
            symbols[v[3]]=[int(v[0],16),int(v[1],16)]
    return sections,symbols
def script(positions,code,data):
    out=''
    for section,after,flag in (('.cs_alias_pattern_lookup','.text',code),('.cs_alias_pattern_rows','.rodata',data)):
        start,size,delta=positions[section];shift=delta if flag else 0
        out+=f'SECTIONS {{ {section} ALIGN(4096) + {start%4096} : {{ . += {shift}; KEEP(*({section})) . = {size+delta}; }} }} INSERT AFTER {after};\n'
    return out
