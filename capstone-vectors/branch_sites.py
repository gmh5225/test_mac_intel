"""Record source coordinates and compiler branch weights from profiled x86 writers."""
from pathlib import Path
import json,gzip,re,subprocess as sp,shlex
def capture(db,merged,out):
    sites={}
    for entry in db:
        src=Path(entry['file'])
        if src.name not in ('X86Vex32Output.c','X86Sse64Output.c'):continue
        args=shlex.split(entry['command'])
        args[args.index('-o')+1]='-'
        ll=sp.check_output(args+['-S','-emit-llvm','-gline-tables-only','-fprofile-use='+str(merged)],cwd=entry['directory'],text=True)
        with gzip.open(out/(src.stem+'.ll.gz'),'wt')as f:f.write(ll)
        md={int(n):value for n,value in re.findall(r'^!(\d+) = (.+)$',ll,re.M)}
        def location(key):
            loc=md[key]
            line=re.search(r'\bline: (\d+)',loc);col=re.search(r'\bcolumn: (\d+)',loc);s=re.search(r'\bscope: !(\d+)',loc)
            if not s:return None
            seen=set();ref=int(s[1])
            while ref not in seen:
                seen.add(ref);node=md[ref]
                fn=re.search(r'!DIFile\(filename: "([^"]+)"',node)
                if fn:return [Path(fn[1]).name,int(line[1])if line else 0,int(col[1])if col else 0]
                link=re.search(r'\bfile: !(\d+)',node) or re.search(r'\bscope: !(\d+)',node)
                if not link:break
                ref=int(link[1])
            return None
        name=None;records=[]
        for row in ll.splitlines():
            if row.startswith('define '):
                m=re.search(r'@([^ (]+)\(',row);name=m[1]if m else None
            elif row=='}':name=None
            if not name or not row.lstrip().startswith('br i1 '):continue
            p=re.search(r'!prof !(\d+)',row);s=re.search(r'!dbg !(\d+)',row)
            if not (p and s):continue
            weights=md[int(p[1])]
            if '"branch_weights"' not in weights:continue
            counts=[int(x)&0xffffffff for x in re.findall(r'i32 (-?\d+)',weights)]
            if len(counts)!=2:continue
            loc=location(int(s[1]))
            if loc:records.append(dict(function=name,source=loc,weights=counts))
        assert records,(src,len(md));sites[src.name]=records
    assert len(sites)==2
    (out/'branch-sites.json').write_text(json.dumps(sites,indent=2)+'\n')
