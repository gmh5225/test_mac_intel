#include <capstone/capstone.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>
#include <cstdio>
int main(int argc, char **argv) {
 if(argc!=4)return 1;
 csh h=0;unsigned bits=std::strtoul(argv[1],nullptr,10);
 if(cs_open(CS_ARCH_X86,bits==64?CS_MODE_64:CS_MODE_32,&h)!=CS_ERR_OK||cs_option(h,CS_OPT_DETAIL,CS_OPT_ON))return 2;
 cs_insn *insn=cs_malloc(h);
 std::ifstream in(argv[2],std::ios::binary), spans(argv[3]);
 std::vector<unsigned char> bytes{std::istreambuf_iterator<char>(in),{}};
 size_t start,n;uint64_t address;
 while(spans>>start>>n>>address) {
  if(start>bytes.size()||n>bytes.size()-start)return 3;
  const unsigned char *cursor=bytes.data()+start;size_t valid=0,vectors=0;
  while(n) {
   if(!cs_disasm_iter(h,&cursor,&n,&address,insn)){++cursor;--n;++address;continue;}
   ++valid;const auto &x=insn->detail->x86;
   for(unsigned i=0;i<x.op_count;++i){
    auto &op=x.operands[i];if(op.type!=X86_OP_REG)continue;
    const char *name=cs_reg_name(h,op.reg);
    if(name && (!std::strncmp(name,"xmm",3)||!std::strncmp(name,"ymm",3)||!std::strncmp(name,"zmm",3))) {++vectors;break;}
   }
  }
  std::printf("%zu %zu\n",valid,vectors);
 }
 cs_free(insn,1);cs_close(&h);
}
