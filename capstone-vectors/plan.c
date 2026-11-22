#include "arch/X86/X86FeatureExtension.h"
#include "arch/X86/X86EvexScanPlan.h"
uint32_t evex_word(const uint8_t *p,size_t n){unsigned id,len;return n>=6 && X86_readEvexScanPlan(p,n,&id,&len)?(id<<8)|len:0;}
