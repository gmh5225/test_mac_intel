from pathlib import Path
import hashlib,json,re,shlex,shutil,subprocess as sp
def sha(z):return hashlib.sha256(z).hexdigest()
def symbols(f):
    wanted=('AArch64_add_vas','AArch64_reg_name','AArch64_getInstruction','ARM_getInstruction','Mips_getInstruction','cs_disasm_iter','X86_getInstruction','X86_disasmIter32','X86_disasmIterText','tryOutput64')
    vals={}
    for row in sp.check_output(['nm','-S',f],text=True).splitlines():
        words=row.split()
        if len(words)==4 and words[-1] in wanted:vals[words[-1]]=[int(words[0],16),int(words[1],16)]
    assert set(vals)==set(wanted)
    return vals
def image_sections(f):
    import struct
    z=f.read_bytes();off=struct.unpack_from('<Q',z,40)[0];width,count,i=struct.unpack_from('<HHH',z,58)
    headers=[struct.unpack_from('<IIQQQQIIQQ',z,off+k*width)for k in range(count)]
    h=headers[i];strings=z[h[4]:h[4]+h[5]]
    out={}
    for h in headers:
        name=strings[h[0]:strings.index(b'\0',h[0])].decode()
        if h[1]==1 and (h[2]&4 or name.startswith(('.rodata','.cs_x86_'))):
            out[name]=dict(start=h[3],length=h[5],sha256=sha(z[h[4]:h[4]+h[5]]))
    return out
def controls(t,build,out,products,command,write):
    current=products['arm64_vas'];base=products['base'];s0=symbols(base);s1=symbols(current)
    diff=s0['AArch64_reg_name'][0]-s1['AArch64_reg_name'][0]
    assert s0['AArch64_add_vas'][0]==s1['AArch64_add_vas'][0] and 0<diff<=128 and diff%16==0
    rows=json.loads((build/'compile_commands.json').read_text())
    c,=[v for v in rows if v['file'].endswith('/arch/AArch64/AArch64Mapping.c')]
    source=Path(c['file']);original=source.read_bytes();tag=b'const char *AArch64_reg_name(csh '
    assert original.count(tag)==1
    attributed=original.replace(tag,('__attribute__((patchable_function_entry(%d,%d)))\n'%(diff,diff)).encode()+tag)
    archive,=list(build.rglob('libcapstone.a'));linked,=list(build.rglob('capstone-product'))
    def members():return {k:sha(sp.check_output(['ar','p',archive,k]))for k in sp.check_output(['ar','t',archive],text=True).splitlines()}
    selectors={k:symbols(v)for k,v in products.items()};sections={k:image_sections(v)for k,v in products.items()};archives={}
    prior=members()
    try:
        for label,data in [('reassembled',original),('aligned',attributed)]:
            source.write_bytes(data)
            command(['cmake','--build',build,'--target','capstone-product','--parallel','4'],'recompile-'+label)
            ar=members();dest=t/(label+'-product');shutil.copy2(linked,dest);products[label]=dest
            selectors[label]=symbols(dest);sections[label]=image_sections(dest);archives[label]=ar
            write('partial-'+label,dict(symbols=selectors,sections=sections,changed_members=[k for k in ar if ar[k]!=prior[k]],controls=[sha(current.read_bytes()),sha(dest.read_bytes())]))
    finally:
        source.write_bytes(original)
        command(['cmake','--build',build,'--target','capstone-product','--parallel','4'],'restore-parser-build')
    assert sha(linked.read_bytes())==sha(current.read_bytes()) and archives['reassembled']==prior
    assert {k for k in prior if archives['aligned'][k]!=prior[k]}=={'AArch64Mapping.c.o'}
    assert selectors['reassembled']==selectors['arm64_vas'] and sections['reassembled']==sections['arm64_vas']
    for k,ref in selectors['base'].items():
        assert selectors['aligned'][k]==[ref[0],selectors['arm64_vas'][k][1]],(k,selectors['aligned'][k],ref)
    assert sections['aligned']['.text']['length']==sections['base']['.text']['length']
    write('placement',dict(bytes=diff,symbols=selectors,sections=sections,baseline_sha=sha(base.read_bytes()),candidate_sha=sha(current.read_bytes()),archives=archives))
