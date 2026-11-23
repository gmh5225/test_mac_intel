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
    unsigned count=0,miss=0,auipc=0,lui=0,jal=0;
    while(n) {
        const uint8_t *start=p;
        if(!cs_disasm_iter(h,&p,&n,&address,i)){size_t skip=std::min<size_t>(2,n);p+=skip;n-=skip;address+=skip;++miss;continue;}
        ++count;if(i->size!=4)continue;
        switch(start[0]&127) {
        case 0x17: if(i->id!=RISCV_INS_AUIPC)return 4; ++auipc;break;
        case 0x37: if(i->id!=RISCV_INS_LUI)return 5; ++lui;break;
        case 0x6f: if(i->id!=RISCV_INS_JAL)return 6; ++jal;break;
        }
    }
    cs_free(i,1);cs_close(&h);std::printf("%u %u %u %u %u\n",count,miss,auipc,lui,jal);
}
