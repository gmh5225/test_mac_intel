import os,sys
from pathlib import Path
extra,cc,*args=sys.argv[1:]
src=Path(args[args.index('-c')+1])
if src.parent.name=='X86' and src.suffix=='.c':
    args.append(extra)
os.execv(cc,[cc,*args])
