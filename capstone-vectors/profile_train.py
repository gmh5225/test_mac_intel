from pathlib import Path
import hashlib,json,os,re,shutil,subprocess as sp
import training_corpus
def train(exe,w,recipes,tool,raw,out):
    programs={};unseen=recipes['forbidden_hashes']
    for arch,group in recipes['packages'].items():
        pkg=w/(arch+'.deb')
        sp.run(['curl','--retry','3','--retry-all-errors','-fsSL',group['url'],'-o',pkg],check=True)
        assert hashlib.sha256(pkg.read_bytes()).hexdigest()==group['package_sha256']
        for name,d in group['programs'].items():
            elf=training_corpus.deb_binary(pkg,name);code=training_corpus.elf_text(elf)
            assert hashlib.sha256(elf).hexdigest()==d['elf_sha256'] and len(code)==d['bytes']
            h=hashlib.sha256(code).hexdigest();assert h==d['sha256'] and h not in unseen
            text=w/'training.text';span=w/'training.tsv';text.write_bytes(code);span.write_text(f"0 {len(code)} {d['address']}\n")
            bits='32' if arch=='i386' else '64'
            results={}
            for mode in (0,1,2):
                for reader in ('capstone','x86_all_' if mode else 'vecbatch'):
                    numbers=sp.check_output([exe,reader,str(mode),'1',text,span,bits],text=True)
                    values=list(map(int,numbers.split()));assert len(values)>=5 and values[2]>1000
                    results[reader+'/'+str(mode)]=values[2:]
            programs[arch+'/'+name]=dict(sha256=h,records=results)
        pkg.unlink()
    profiles=sorted(raw.glob('*.profraw'));assert profiles
    merged=w/'capstone.profdata';sp.run([tool,'merge','-o',merged,*profiles],check=True)
    shown=sp.check_output([tool,'show','--all-functions','--counts',merged],text=True)
    import gzip
    with gzip.open(out/'function-counters.txt.gz','wt')as f:f.write(shown)
    # Clang can inline or coalesce the forwarding wrapper. Verify the counter
    # of a function doing the work in each decoder or formatter family.
    functions={}
    for family,names in {
        'i386 formatting':('tryOutput32',),
        'AMD64 formatting':('tryOutput64',),
        'register access':('X86_reg_access',),
        'ordinary decoder':('X86_getInstruction','_getInstruction','decodeInstructionFull','getIDWithAttrMask','readModRM')
    }.items():
        entries={}
        for heading,data in re.findall(r'^  (\S[^\n]*):\n((?:    [^\n]+\n)+)',shown,re.M):
            # Clang versions emit either an object path plus semicolon or a bare symbol.
            symbol=heading.rsplit(';',1)[-1].split('.')[0]
            if symbol not in names:continue
            counters=[int(n) for line in data.splitlines() if 'Block counts:' in line or 'Function count:' in line for n in re.findall(r'[0-9]+',line.split(':',1)[1])]
            if counters:entries[heading]=max(counters)
        assert entries and max(entries.values())>100,(family,entries)
        functions[family]=entries
    (out/'profile.json').write_text(json.dumps(dict(training=programs,functions=functions,bytes=merged.stat().st_size,sha256=hashlib.sha256(merged.read_bytes()).hexdigest(),tool=str(tool),raw=len(profiles)),indent=2)+'\n')
    return merged
