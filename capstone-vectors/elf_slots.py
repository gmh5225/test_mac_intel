from pathlib import Path
import hashlib,shutil,subprocess
from elftools.elf.elffile import ELFFile

def run(*args,cwd=None):subprocess.run(args,cwd=cwd,check=True)
def sh(data):return hashlib.sha256(data).hexdigest()
def capture(file):
    with file.open('rb') as handle:
        elf=ELFFile(handle);out={}
        for sect in elf.iter_sections():
            name=sect.name;flags=sect['sh_flags']
            if not (flags&2) or name.startswith(('.eh_frame','.note.')):continue
            assert not (flags&0x400),name
            group='zero' if sect['sh_type']=='SHT_NOBITS' else 'exec' if flags&4 else 'write' if flags&1 else 'const'
            out[name]=(group,sect['sh_addralign'],sect['sh_size'])
        return out

def plan(versions,archives,work,ar,objcopy,members):
    slots={}; mergeable=set()
    for variant in versions:
        for member in members:
            rows=capture(versions[variant]/member)
            with (versions[variant]/member).open('rb') as stream:
                elf=ELFFile(stream)
                for sect in elf.iter_sections():
                    if sect.name in rows and sect['sh_flags']&16:
                        assert rows[sect.name][0]=='const'
                        mergeable.add((member,sect.name))

            for section,(group,alignment,size) in rows.items():
                k=member,section;prev=slots.get(k,(group,1,0));assert prev[0]==group
                slots[k]=(group,max(alignment,prev[1]),max(size,prev[2]))
    identifiers={k:'csprobe_'+str(i)for i,k in enumerate(sorted(slots))}
    script=work/'diagnostic.ld'
    lines=[]
    for group,after in [('exec','.text'),('const','.rodata'),('write','.data'),('zero','.bss')]:
        records=[(k,v)for k,v in sorted(slots.items()) if v[0]==group and v[2]>0]
        if not records:continue
        lines+=['SECTIONS {','.csprobe_'+group+' : ALIGN(64) {']
        for k,(_,alignment,size) in records:
            ident=identifiers[k]
            lines+=['. = ALIGN('+str(max(64,alignment))+');',ident+'_start = .;',
                    'KEEP(*(.probe_'+ident+'))',
                    '. = MAX(., '+ident+'_start + '+str(size)+');',ident+'_end = .;']
        lines+=['}', '} INSERT AFTER '+after+';']
    script.write_text('\n'.join(lines)+'\n')
    prepared={}
    for version,dirpath in versions.items():
        dest=work/('padded-'+version);dest.mkdir()
        lib=dest/'libcapstone.a';shutil.copy2(archives[version],lib)
        for member in members:
            rows=capture(dirpath/member);opts=[]
            for sect in rows:
                flags=',alloc,load,readonly,data,contents' if (member,sect) in mergeable else ''
                opts+=['--rename-section',sect+'=.probe_'+identifiers[(member,sect)]+flags]
            run(objcopy,*opts,dirpath/member,dest/member)
        run(ar,'rcs',lib,*[dest/k for k in members])
        assert subprocess.check_output([ar,'t',archives[version]])==subprocess.check_output([ar,'t',lib])
        prepared[version]=lib
    return prepared,script

def symbols(file):
    out={};sections={};repeated=set()
    with file.open('rb') as f:
        elf=ELFFile(f);symtab=elf.get_section_by_name('.symtab')
        for item in symtab.iter_symbols():
            if item['st_info']['type']!='STT_FUNC' or not isinstance(item['st_shndx'],int):continue
            section=elf.get_section(item['st_shndx']);n=item['st_size'];v=item['st_value'];start=v-section['sh_addr']
            f.seek(section['sh_offset']+start)
            if item.name in out: repeated.add(item.name)
            out[item.name]=[v,n,sh(f.read(n))]
        for section in elf.iter_sections():
            if section['sh_flags']&2:sections[section.name]=[section['sh_addr'],section['sh_size']]
    return {k:v for k,v in out.items()if k not in repeated},sections
