"""Count real decoder entries per instruction in a separate, untimed library."""
from pathlib import Path
def build(tree,b,out,base,driver,run):
    for file,functions in [('X86DisassemblerDecoder.c',[('decodeScanResultFallback(csh ud,',0),('decodeScanResultGeneric(csh ud,',1),('static bool decodeGenericScan(',2)]),
                           ('X86Mapping.c',[('X86_decodeFeatureExtensionSlow(csh handle,',3)]),
                           ('X86EvexScan.c',[])]:
        f=tree/'arch/X86'/file;s=f.read_text();s='extern unsigned profile_stages[5];\n'+s
        for name,index in functions:
            assert s.count(name)==1,name
            a=s.index('\n{',s.index(name))+2
            s=s[:a]+'\n\t++profile_stages['+str(index)+'];'+s[a:]
        if file=='X86EvexScan.c':
            tag='return X86_FEATURE_DECODED;';assert s.count(tag)==1
            s=s.replace(tag,'++profile_stages[4];\n\t\t\t'+tag)
        f.write_text(s)
    run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build-observed')
    run(['clang++','-O2','-std=c++17','-I',tree/'include',driver,b/'libcapstone.a','-lm','-o',out],'link-observer')
