#define X86_scanNativeBatch X86_observedNativeBatch
#include "arch/X86/X86BatchScan.c"
uint32_t projected_word(const uint8_t *p,size_t n){return readFirst64(p,n);}
