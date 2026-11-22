from pathlib import Path
def install(s):
    fallback=s/'arch/X86/X86MemoryFallback32.c';original=fallback.read_text();a='return cs_decode_full_insn(handle, code, size, insn, insn_size, batch);';assert original.count(a)==1;fallback.write_text(original.replace(a,'(void)batch; return false;'))
    with (s/'arch/X86/X86Vex32Output.c').open('a') as f:
        f.write('\nbool observed_sib(csh h,const uint8_t *p,size_t n,cs_insn *i,uint16_t *len) {\ncs_struct *cs=(cs_struct *)(uintptr_t)h;\nreturn n && (tryOutput32(cs,p,n,i,len)||X86_decodeOutputMiss32(cs,p,n,i,len,false));\n}\n')
