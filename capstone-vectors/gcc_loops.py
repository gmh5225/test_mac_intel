"""Capture only the batch-reader unswitch report without changing timed objects."""
from pathlib import Path
import gzip,hashlib,json,re,shlex,subprocess as sp


def capture(build,object_file,work,evidence,label,save,run):
    commands=json.loads((build/'compile_commands.json').read_text())
    entries=[x for x in commands if Path(x['file']).name=='X86DisassemblerDecoder.c']
    assert len(entries)==1
    entry=entries[0];args=entry.get('arguments') or shlex.split(entry['command'])
    target=work/(label+'-diagnostic.o');raw=work/(label+'-unswitch.txt')
    args[args.index('-o')+1]=str(target)
    args.append('-fdump-tree-unswitch-details='+str(raw))
    run(args,'gcc-unswitch-'+label,entry['directory'])
    sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
    same=sha(target)==sha(object_file)
    text=raw.read_text()
    match=re.search(r'^;; Function X86_scanBatch\b.*?(?=^;; Function |\Z)',text,re.M|re.S)
    assert match,'missing X86_scanBatch optimization report'
    block=match[0]
    with gzip.open(evidence/(label+'-batch-unswitch.txt.gz'),'wt')as out:out.write(block)
    events=[line for line in block.splitlines()if re.search('unswitch|version|unroll|duplicat',line,re.I)]
    save(label+'-batch-optimizer.json',dict(timed_object_unchanged=same,original_object_sha256=sha(object_file),
         diagnostic_object_sha256=sha(target),full_dump_sha256=sha(raw),full_dump_bytes=raw.stat().st_size,
         batch_dump_bytes=len(block),events=events))
    target.unlink();raw.unlink()
    assert same,'diagnostic compiler flags changed the object'
