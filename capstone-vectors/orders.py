from pathlib import Path
from elftools.elf.elffile import ELFFile
from symbol_layout import symbols
import hashlib, os, shutil, subprocess as sp

def inspect_orders(w,lib,base,r,maps,q,ice_lib,flags,run,get,sha,save,build):
    ar=shutil.which('ar')
    linkers={'default':[], 'bfd':['-fuse-ld=bfd']}
    if shutil.which('ld.lld'):
        linkers['lld']=['-fuse-ld=lld']
    versions={k:get(k,'--version').splitlines()[0] for k in ('ar','ld.bfd','ld.lld') if shutil.which(k)}
    banks=['.cs_x86_i386_text','.cs_x86_memory_fallback32_text','.cs_x86_register_fallback32_text',
           '.cs_x86_amd64_text','.cs_x86_native_batch_text','.cs_x86_vector_fallback64_text',
           '.cs_x86_i386_rodata','.cs_x86_memory_fallback32_rodata','.cs_x86_register_fallback32_rodata',
           '.cs_x86_indirect64_rodata','.cs_x86_indirect64_text']
    arch=os.uname().machine;extra='X86IndirectFallback64.c.o';tables={};archives={};images={}
    stream=w/'rip.bin';stream.write_bytes(bytes.fromhex('ff 15 01 00 00 00 ff 25 f0 ff ff ff c3'))
    extents=w/'rip.tsv';extents.write_text('0 13 1048576\n')
    def link_and_read(library,kind):
        images[kind]={}
        for linker,opts in linkers.items():
            out=w/'ordinary-linked'
            run('clang++',*opts,w/'driver.o',library,ice_lib,*flags,'-o',out)
            with out.open('rb')as fh:
                elf=ELFFile(fh);sections={}
                for n in banks:
                    sec=elf.get_section_by_name(n)
                    if sec:sections[n]=[sec['sh_addr'],sec['sh_size'],hashlib.sha256(sec.data()).hexdigest()]
            assert set(banks[:9])<=sections.keys()
            samples={f'{bits}/{mode}':list(map(int,get(out,'private',str(mode),'1',stream,extents,str(bits)).split()))[2:] for bits in (32,64) for mode in (0,1,2)}
            assert all(row[0]==3 and row[1]==0 for row in samples.values())
            images[kind][linker]=dict(sha256=sha(out),sections=sections,functions=symbols(out),records=samples)
            out.unlink()
    def snapshot(label):
        dest=w/label;dest.mkdir()
        names=get(ar,'t',lib).splitlines()
        assert len(set(names))==len(names) and all(Path(n).name==n for n in names)
        run(ar,'x',lib,cwd=dest)
        tables[label]=names
        archives[label]=dict(sha256=sha(lib),members={n:sha(dest/n) for n in names})
        link_and_read(lib,label)
    snapshot('release')
    assert sha(r/'candidate.patch')==q['sha256'] and maps['base']['commit']==q['parent']
    run('git','-C',base,'apply','--index',r/'candidate.patch')
    assert get('git','-C',base,'write-tree').strip()==q['tree']
    run('cmake','--build',build,'--target','capstone_static','--parallel','4')
    snapshot('candidate')
    order=tables['candidate'];old=tables['release']
    if arch=='aarch64':
        assert [n for n in order if n!=extra]==old and extra in order
        assert {n for n in old if archives['release']['members'][n]!=archives['candidate']['members'][n]}=={'X86VectorFallback64.c.o'}
        proposals={'repacked':order,'first':[extra,*old],'last':[*old,extra]}
        for name in ('X86Vex32Output.c.o','X86Sse64Output.c.o','X86VectorFallback64.c.o','X86RegisterFallback32.c.o','X86EvexMemoryOutput.c.o'):
            i=old.index(name);tag=name.removesuffix('.c.o')
            proposals['before-'+tag]=old[:i]+[extra]+old[i:]
            proposals['after-'+tag]=old[:i+1]+[extra]+old[i+1:]
        cache={}
        for tag,seq in proposals.items():
            assert [n for n in seq if n!=extra]==old
            if tuple(seq) in cache:
                images[tag]=images[cache[tuple(seq)]];continue
            dest=w/(tag+'.a')
            run(ar,'rcsD',dest,*seq,cwd=w/'candidate')
            assert get(ar,'t',dest).splitlines()==seq
            link_and_read(dest,tag)
            dest.unlink()
            cache[tuple(seq)]=tag
        assert all(images['repacked'][k]==images['candidate'][k] for k in linkers)
    else:
        assert arch=='x86_64' and tables['candidate']==old and archives['release']==archives['candidate'] and images['release']==images['candidate']
    for tag,vals in images.items():
        assert all(vals[k]['records']==images['release'][k]['records'] for k in linkers)
    save('geometry',dict(host=arch,compiler=get('clang','--version').splitlines()[0],linkers=versions,tables=tables,archives=archives,images=images,source=maps))
    save('complete',dict(complete=True,source=maps,host=arch,orders=len(images),linkers=list(linkers)))
