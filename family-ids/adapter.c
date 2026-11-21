#include "arch/X86/X86ScanAdapter.h"
#include <stdio.h>
typedef struct State { csh handle; unsigned calls; } State;
static uint32_t change_mode(void *ctx,const uint8_t *p,size_t n){
  State *state=ctx;
  if(n<6||p[0]!=0x62||cs_option(state->handle,CS_OPT_MODE,CS_MODE_64)!=CS_ERR_OK) return 0;
  ++state->calls;return (X86_INS_VMOVAPS<<8)|6;
}
int main(void){
  static const uint8_t bytes[]={0x90,0x90,0x62,0xf1,0x7c,0x48,0x28,0x00,0x48,0x90,0xc3};
  State state={0};if(cs_open(CS_ARCH_X86,CS_MODE_32,&state.handle) || cs_option(state.handle,CS_OPT_TEXT,CS_OPT_OFF))return 1;
  if(!X86_setScanAdapter(state.handle,CS_MODE_32,change_mode,&state))return 2;
  uint32_t out[9]={0};X86ScanBatchResult b=X86_scanBatch(state.handle,bytes,sizeof(bytes),0x1000,out,9);
  const uint32_t want[]={X86_INS_NOP<<8|1,X86_INS_NOP<<8|1,X86_INS_VMOVAPS<<8|6,X86_INS_NOP<<8|2,X86_INS_RET<<8|1};
  if(state.calls!=1||b.count!=5||b.bytes!=sizeof(bytes)||out[5])return 3;
  for(size_t i=0;i<5;++i)if(out[i]!=want[i]){fprintf(stderr,"%zu %u %u\n",i,out[i],want[i]);return 4;}
  cs_close(&state.handle);puts("callback changed CS_MODE_32 to CS_MODE_64 between terminal runs; counts, IDs and cursor verified");
}
