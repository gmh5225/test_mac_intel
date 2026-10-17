"""Give this component's C definitions one private link-time namespace."""
from pathlib import Path
import hashlib,re,shutil
ENTRY='neverd_recovered_ugrep_main'
PREFIX='neverd_ugrep_native_'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def isolate(library,objects,archives,toolbin,run,logs):
    raw_objects=library/'raw-objects';raw_objects.mkdir()
    raw_archives=library/'raw-dependency-archives';raw_archives.mkdir()
    for path in objects:shutil.copyfile(path,raw_objects/path.name)
    for path in archives:shutil.copyfile(path,raw_archives/path.name)
    run('private-symbol-inputs',[toolbin/'llvm-nm','--extern-only','--defined-only','--format=posix',*objects,*archives])
    names=set()
    for line in (logs/'private-symbol-inputs.stdout').read_text().splitlines():
        fields=line.split()
        if len(fields)<2 or len(fields[1])!=1 or not fields[1].isalpha():continue
        name=fields[0]
        if name.startswith('_Z') or name==ENTRY:continue
        assert re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.$]*',name),name
        names.add(name)
    assert {'pcre2_compile_8','inflate','ZSTD_decompress','BrotliDecoderDecompress'}<=names
    mapping={name:PREFIX+name for name in sorted(names)}
    assert len(mapping)>100 and not any(name.startswith(PREFIX) for name in mapping)
    symbols=library/'private-symbols.txt'
    symbols.write_text(''.join(old+' '+new+'\n' for old,new in mapping.items()))
    for index,path in enumerate(objects):
        run('private-program-object-'+str(index),[toolbin/'llvm-objcopy','--redefine-syms='+str(symbols),path])
    evidence=[]
    for index,path in enumerate(archives):
        before=sha(path)
        result=run('private-archive-members-'+str(index),[toolbin/'llvm-ar','t',path])
        members=result.stdout.decode().splitlines()
        assert members and len(members)<2048 and len(members)==len(set(members))
        assert all(Path(name).name==name and name not in ['.','..'] for name in members)
        work=logs/('private-archive-objects-'+str(index));work.mkdir()
        run('private-archive-extract-'+str(index),[toolbin/'llvm-ar','x',path],work)
        assert {p.name for p in work.iterdir()}==set(members)
        for ordinal,name in enumerate(members):
            run('private-dependency-object-'+str(index)+'-'+str(ordinal),[toolbin/'llvm-objcopy','--redefine-syms='+str(symbols),work/name])
        path.unlink()
        run('private-archive-rebuild-'+str(index),[toolbin/'llvm-ar','rcs',path,*[work/name for name in members]])
        evidence.append(dict(archive=path.name,before_sha256=before,after_sha256=sha(path),members=members))
    run('private-symbol-output',[toolbin/'llvm-nm','--extern-only','--defined-only','--format=posix',*objects,*archives])
    output=set()
    for line in (logs/'private-symbol-output.stdout').read_text().splitlines():
        fields=line.split()
        if len(fields)>=2 and len(fields[1])==1 and fields[1].isalpha():output.add(fields[0])
    assert not names&output and set(mapping.values())<=output
    assert ENTRY in output and not any(PREFIX+name in output for name in [ENTRY,'malloc','free','pthread_create'])
    return dict(status='component_c_definitions_privately_namespaced',symbols=len(mapping),mapping_sha256=sha(symbols),
        private_prefix=PREFIX,cxx_runtime_renamed=False,entry_renamed=False,dependency_archives=evidence)
