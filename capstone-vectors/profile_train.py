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
    functions={}
    for sym in ('tryOutput32','tryOutput64','X86_reg_access','X86_getInstruction'):
        blocks=re.findall(r'^\s{2}([^\n]*'+sym+r'):\s*\n((?:    [^\n]+\n)+)',shown,re.M)
        assert blocks,(sym,shown[:500])
        hits=max(int(n) for _,t in blocks for line in t.splitlines() if 'Block counts:' in line or 'Function count:' in line for n in re.findall(r'[0-9]+',line.split(':',1)[1]))
        assert hits>100, (sym,hits)
        functions[sym]=blocks
    (out/'profile.json').write_text(json.dumps(dict(training=programs,functions=functions,bytes=merged.stat().st_size,sha256=hashlib.sha256(merged.read_bytes()).hexdigest(),tool=str(tool),raw=len(profiles)),indent=2)+'\n')
    return merged
