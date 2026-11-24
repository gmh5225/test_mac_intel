"""Make a diagnostic pair with the same downstream addresses in both normal product links."""
from pathlib import Path
import hashlib,shlex,shutil,subprocess as sp
from elftools.elf.elffile import ELFFile

SECTION='.cs_x86_memory_fallback32_text'
MEMBER='X86MemoryFallback32.c.o'
def read_sections(path):
    with path.open('rb') as f:
        elf=ELFFile(f)
        return {s.name:(s['sh_addr'],s['sh_size'],hashlib.sha256(s.data()).hexdigest())
                for s in elf.iter_sections() if s['sh_flags']&2 and s['sh_type']!='SHT_NOBITS'}

def pair(build,t,products,archive,save):
    def get(*a,cwd=None):return sp.check_output(a,text=True,cwd=cwd)
    def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
    archives={k:t/(k+'.a')for k in ('base','selector')}
    sizes={k:read_sections(products[k])[SECTION][1] for k in archives}
    size=max(sizes.values());log={}
    line=get('ninja','-C',build,'-t','commands','capstone-product').splitlines()[-1]
    args=shlex.split(line)
    begin=next(i for i,v in enumerate(args)if Path(v).name in ('clang++','clang++-18','c++') or Path(v).name.startswith('clang++-'))
    end=next((i for i in range(begin+1,len(args))if args[i]=='&&'),len(args))
    link=args[begin:end];pos=link.index('-o')+1
    idx,=[i for i,v in enumerate(link)if v.endswith('.a') and (build/v).resolve()==archive.resolve()]
    save('link-command',dict(argv=link,archive_argument=idx,output_argument=pos))
    for k,original in archives.items():
        directory=t/('match-'+k);directory.mkdir();obj=directory/MEMBER
        obj.write_bytes(sp.check_output(['ar','p',original,MEMBER]))
        names=get('ar','t',original).splitlines();assert names.count(MEMBER)==1
        new=directory/'libcapstone.a';shutil.copyfile(original,new)
        with obj.open('rb')as f:
            elf=ELFFile(f);sec=elf.get_section_by_name(SECTION);body=sec.data()
        assert len(body)==sizes[k],(len(body),sizes)
        relocations={}
        if len(body)<size:
            fill=directory/'filled';fill.write_bytes(body+bytes(size-len(body)))
            tmp=directory/'updated.o'
            sp.run(['objcopy','--update-section',SECTION+'='+str(fill),obj,tmp],check=True)
            from extend import extend
            relocations['preserved']=extend(obj,SECTION,size-len(body))
            # Compare the discarded experimental objcopy image to its input.
            with tmp.open('rb')as f:
                e=ELFFile(f);idx=e.get_section_index(SECTION)
                relocations['objcopy']={z.name:z.num_relocations()for z in e.iter_sections()
                    if z['sh_type'] in ('SHT_RELA','SHT_REL') and z['sh_info']==idx}
            sp.run(['ar','rDs',new,obj],check=True)
        assert get('ar','t',new).splitlines()==names
        assert all(sp.check_output(['ar','p',original,n])==sp.check_output(['ar','p',new,n]) for n in names if n!=MEMBER)
        raw=directory/'raw'
        for archive_path,target in [(original,raw),(new,directory/'matched')]:
            argv=list(link);argv[pos]=str(target);argv[idx]=str(archive_path)
            sp.run(argv,check=True,cwd=build)
        assert sha(raw)==sha(products[k]),('link replay changed executable',k)
        products['matched-'+k]=directory/'matched';before=read_sections(raw);after=read_sections(products['matched-'+k])
        log[k]=dict(relocations=relocations,before=before,after=after,pad=size-len(body),unchanged_executable=sha(raw)==sha(products['matched-'+k]),input_sha256=sha(original),output_sha256=sha(new))
    base=log['base']['after'];new=log['selector']['after']
    scan=['.cs_x86_native_batch_text','.cs_x86_batch32_text','.cs_x86_batch64_text']
    check=dict(allocated_extent_differences=[k for k,v in base.items()if new.get(k,(None,None))[:2]!=v[:2]],
               scanner_sections_identical=all(base[k]==new[k]for k in scan),
               scanner_sections={k:{'base':base[k],'selector':new[k]}for k in scan})
    save('matched-layout',dict(hosts=log,check=check))
    assert check['scanner_sections_identical'] and all(base[k][:2]==new[k][:2]for k in ('.text','.rodata',SECTION))
