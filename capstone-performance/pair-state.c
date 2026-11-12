#include "arch/X86/X86Mapping.h"
#include <stdint.h>
#include <stdio.h>
#include <limits.h>
int main(void) {
  for (unsigned key=0;key<=65536;key++) {
    unsigned id=key==65536?UINT_MAX:key;
    for(unsigned att=0;att<2;att++) for(unsigned alias=0;alias<2;alias++)
      for(unsigned out=0;out<8;out++){
        x86_reg regs[2]={X86_REG_YMM2,X86_REG_MM3};
        enum cs_ac_type access[2]={CS_AC_WRITE,CS_AC_READ_WRITE};
        enum cs_ac_type *a=(out&1)?&access[0]:NULL;
        enum cs_ac_type *b=(out&2)?&access[(out&4)?0:1]:NULL;
        bool got=(att?X86_insn_reg_att2:X86_insn_reg_intel2)(id,&regs[0],a,&regs[alias?0:1],b);
        uint16_t record[5]={got,regs[0],regs[1],access[0],access[1]};
        if(fwrite(record,sizeof(record),1,stdout)!=1) return 2;
      }
  }
  return 0;
}
