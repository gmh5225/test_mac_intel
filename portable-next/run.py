from pathlib import Path
import collections,hashlib,json,os,shutil,struct,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;root=r.parent;s=root/'source';e=root/'evidence';e.mkdir(exist_ok=True)
q=json.loads((r/'source.json').read_text())
def sha(b):return hashlib.sha256(b).hexdigest()
def git(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def save(k,v):(e/(k+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def token_hash(data):
    import re
    pattern=rb'''(?:u8|[uUL])?"(?:\\.|[^"\\])*"|(?:u8|[uUL])?'(?:\\.|[^'\\])*'|[a-zA-Z_$][\w$]*|[0-9][\w.]*|>>=|<<=|\.\.\.|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||[+*/%&|^!-]=|##|[^\s]'''
    return sha(b'\0'.join(re.findall(pattern,data)))
def sections(data):
    machine,n=struct.unpack_from('<HH',data);assert machine in (0x14c,0x8664)
    table,symbols=struct.unpack_from('<II',data,8);strings=table+18*symbols
    opt,=struct.unpack_from('<H',data,16);out=[]
    def name(offset):
        start=strings+offset
        return data[start:data.index(b'\0',start)].decode()
    def symbol(i):
        h=data[table+18*i:table+18*i+8]
        return name(int.from_bytes(h[4:],'little')) if h[:4]==bytes(4) else h.rstrip(b'\0').decode()
    for i in range(n):
        at=20+opt+40*i;short=data[at:at+8].rstrip(b'\0').decode()
        sec=name(int(short[1:])) if short.startswith('/') else short
        if sec.startswith(('.debug','.chks64')):continue
        length,raw,rel=struct.unpack_from('<III',data,at+16)
        count,=struct.unpack_from('<H',data,at+32);flags,=struct.unpack_from('<I',data,at+36)
        payload=data[raw:raw+length] if raw else b''
        reloc=[]
        for j in range(count):
            offset,idx,kind=struct.unpack_from('<IIH',data,rel+10*j)
            reloc.append((offset,kind,symbol(idx)))
        out.append(dict(name=sec,length=length,content=sha(payload),references=sha(json.dumps(reloc).encode()),raw_name=short,flags=flags))
    return out
targets=('X86VexRegisterImmediate.c','X86PlainEvexOutput.c')
w=Path(tempfile.mkdtemp());b=w/'build';rows={}
try:
    assert git('rev-parse','HEAD')==q['base']['commit']
    flags=['-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON']
    for tag in ('base','nested','base-repeat','candidate'):
        git('restore','--source=HEAD','--staged','--worktree','--','.')
        ref=q['base' if tag=='base-repeat' else tag]
        if tag in ('nested','candidate'):
            raw=sp.check_output(['git','-C',root,'cat-file','blob','HEAD:portable-next/'+tag+'.patch'])
            assert sha(raw)==ref['sha256'];p=w/'change.patch';p.write_bytes(raw);git('apply','--index',p)
        assert git('write-tree')==ref['tree']
        sp.run(['cmake','-G','Ninja','-S',s,'-B',b,*flags],check=True)
        jobs={Path(j['file']).name:j for j in json.loads((b/'compile_commands.json').read_text()) if Path(j['file']).name in targets}
        assert set(jobs)==set(targets)
        vals={}
        for f,j in jobs.items():
            command=j['command'];cwd=j['directory'];out=w/'same-output.obj'
            assert 'cl.exe' in command.lower() and 'X86_FIXED_OUTPUT_PRECHECKED' not in command
            pre=sp.check_output(command+' /EP',cwd=cwd)
            sp.run(command+' /Brepro /Fo"'+str(out)+'"',cwd=cwd,check=True,stdout=sp.DEVNULL)
            data=out.read_bytes();vals[f]=dict(pre=token_hash(pre),raw=sha(data),sections=sections(data));out.unlink()
        rows[tag]=vals;save('stages',rows)
    effects={}
    for tag,vals in rows.items():
        effects[tag]={}
        for f,row in vals.items():
            base=rows['base'][f]
            a,c=[v['sections'] for v in (base,row)]
            diffs=[]
            for i in range(max(len(a),len(c))):
                x=a[i] if i<len(a) else {};y=c[i] if i<len(c) else {}
                if x!=y:diffs.append(dict(index=i,section=y.get('name',x.get('name')),fields=[z for z in sorted(set(x)|set(y)) if x.get(z)!=y.get(z)]))
            effects[tag][f]=dict(same_pre=base['pre']==row['pre'],same_obj=base['raw']==row['raw'],differing_sections=diffs)
    save('effects',effects)
    for tag in ('base-repeat','candidate'):
        for v in effects[tag].values():assert v['same_pre'] and not v['differing_sections'],(tag,v)
    save('complete',dict(complete=True,source=q,targets=targets,arch=os.environ.get('VSCMD_ARG_TGT_ARCH'),effects=effects))
finally:
    size=sum(p.stat().st_size for p in w.rglob('*') if p.is_file() and not p.is_symlink());shutil.rmtree(w);save('cleanup',dict(bytes=size,removed=not w.exists()))
