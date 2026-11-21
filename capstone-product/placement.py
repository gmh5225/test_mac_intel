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
    compiler=shlex.split(c['command']);cd=Path(c['directory']);asm=t/'mapping.s'
    compiler[compiler.index('-c')]='-S';compiler[compiler.index('-o')+1]=str(asm)
    command(compiler,'emit-mapping-assembly',cd);original=asm.read_text()
    marker=re.search(r'^\s*\.size\s+AArch64_add_vas,[^\n]*$',original,re.M)
    assert marker,original[original.index('AArch64_add_vas:'):][:100]
    tail=marker.end();padded=original[:tail]+'\n\t.fill '+str(diff)+', 1, 0x90'+original[tail:]
    archive,=list(build.rglob('libcapstone.a'))
    cmds=sp.check_output(['ninja','-C',build,'-t','commands','capstone-product'],text=True).splitlines()
    cmd=shlex.split(cmds[-1]);cmd=cmd[next(i for i,v in enumerate(cmd)if Path(v).name.startswith('clang++')):]
    if '&&'in cmd:cmd=cmd[:cmd.index('&&')]
    lib,=[k for k,x in enumerate(cmd) if x.endswith('/libcapstone.a') or x=='libcapstone.a']
    members=sp.check_output(['ar','t',archive],text=True).splitlines()
    which='AArch64Mapping.c.o';assert members.count(which)==1
    selectors={k:symbols(v)for k,v in products.items()}
    sections={k:image_sections(v)for k,v in products.items()};archives={}
    for label,code in [('reassembled',original),('aligned',padded)]:
        path=t/label;path.mkdir();s=path/'mapping.s';s.write_text(code);o=path/which
        command([compiler[0],'-c',s,'-o',o],'assemble-'+label)
        ar=path/'libcapstone.a';shutil.copy2(archive,ar);command(['ar','r',ar,o],'replace-'+label)
        names=sp.check_output(['ar','t',ar],text=True).splitlines();assert names==members
        ar_members={k:sha(sp.check_output(['ar','p',ar,k]))for k in members}
        archives[label]=ar_members
        dest=path/'product';link=cmd[:];link[link.index('-o')+1]=str(dest);link[lib]=str(ar)
        command(link,'link-'+label,build);products[label]=dest;selectors[label]=symbols(dest);sections[label]=image_sections(dest)
    assert {k for k in members if archives['aligned'][k]!=archives['reassembled'][k]}=={which}
    assert selectors['arm64_vas']==selectors['reassembled'] and sections['arm64_vas']==sections['reassembled']
    # The function bodies remain the candidate's sizes. Only placement is adjusted.
    for k,original_symbol in selectors['base'].items():
        assert selectors['aligned'][k]==[original_symbol[0],selectors['arm64_vas'][k][1]],(k,selectors['aligned'][k],original_symbol)
    assert sections['aligned']['.text']['length']==sections['base']['.text']['length']
    write('placement',dict(bytes=diff,symbols=selectors,sections=sections,baseline_sha=sha(base.read_bytes()),candidate_sha=sha(current.read_bytes()),archives=archives))
