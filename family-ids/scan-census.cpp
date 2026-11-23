#include <capstone/capstone.h>
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>
int main(int argc,char **argv) {
    if (argc!=2) return 1;
    std::ifstream file(argv[1],std::ios::binary);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)),{});
    csh h;
    if(bytes.empty() || cs_open(CS_ARCH_RISCV,cs_mode(CS_MODE_RISCV64|CS_MODE_RISCV_C|CS_MODE_RISCV_FD|CS_MODE_RISCV_A),&h)) return 2;
    cs_option(h,CS_OPT_TEXT,CS_OPT_OFF);cs_insn *i=cs_malloc(h);
    if(!i) return 3;
    const uint8_t *p=bytes.data();size_t n=bytes.size();uint64_t address=1048576;
    unsigned count=0,miss=0,branches=0,memory=0;
    while(n) {
        const uint8_t *start=p;
        if(!cs_disasm_iter(h,&p,&n,&address,i)){size_t skip=std::min<size_t>(2,n);p+=skip;n-=skip;address+=skip;++miss;continue;}
        ++count;if(i->size!=2)continue;
        const unsigned key=((start[1]>>5)<<2)|(start[0]&3);
        const unsigned ids[32] = {0,0,0,0,0,0,0,0,RISCV_INS_C_LW,0,0,0,
            0,0,0,0,0,0,0,0,0,RISCV_INS_C_J,0,0,RISCV_INS_C_SW,
            RISCV_INS_C_BEQZ,RISCV_INS_C_SWSP,0,0,RISCV_INS_C_BNEZ,0,0};
        if(ids[key]){if(i->id!=ids[key])return 4;if((key&3)==1)++branches;else ++memory;}
    }
    cs_free(i,1);cs_close(&h);std::printf("%u %u %u %u\n",count,miss,branches,memory);
}
