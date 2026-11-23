import os,sys
from pathlib import Path
extra,cc,*args=sys.argv[1:]
src=Path(args[args.index('-c')+1])
formatting=any(x in src.stem for x in ('Output','Fallback','InstPrinter','VexRegisterImmediate'))
if src.parent.name=='X86' and src.suffix=='.c' and (extra.startswith('-fprofile-generate=') or formatting):
    args.append(extra)
os.execv(cc,[cc,*args])
