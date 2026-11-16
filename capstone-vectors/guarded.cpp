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
 if(std::getenv("CAPSTONE_PROBE_NO_TEXT"))cs_option(h,CS_OPT_TEXT,CS_OPT_OFF);
 cs_insn *insn=cs_malloc(h);
 std::ifstream in(argv[2],std::ios::binary), spans(argv[3]);
 std::vector<unsigned char> bytes{std::istreambuf_iterator<char>(in),{}};
 size_t start,n;uint64_t address;
 while(spans>>start>>n>>address) {
  if(start>bytes.size()||n>bytes.size()-start)return 3;
  const unsigned char *cursor=bytes.data()+start;size_t valid=0,vectors=0;
  while(n) {
   volatile size_t before_n=n;
   volatile uintptr_t before_cursor=reinterpret_cast<uintptr_t>(cursor);
   volatile uint64_t before_ip=address;
   const bool ok=cs_disasm_iter(h,&cursor,&n,&address,insn);
   const bool bad=ok ? (!insn->size || insn->size>before_n || n!=before_n-insn->size ||
      reinterpret_cast<uintptr_t>(cursor)!=before_cursor+insn->size || address!=before_ip+insn->size) :
      (n!=before_n || reinterpret_cast<uintptr_t>(cursor)!=before_cursor || address!=before_ip);
   if(bad) {
    std::fprintf(stderr,"violation ok=%d start=%zu span_length=%zu old_remaining=%zu new_remaining=%zu old_cursor=%llx new_cursor=%llx old_ip=%llx new_ip=%llx insn_size=%u id=%u\n",ok,start,size_t(before_n),size_t(before_n),n,(unsigned long long)before_cursor,(unsigned long long)reinterpret_cast<uintptr_t>(cursor),(unsigned long long)before_ip,(unsigned long long)address,unsigned(insn->size),insn->id);
    const auto pos=before_cursor-reinterpret_cast<uintptr_t>(bytes.data());
    if(pos<bytes.size()) {
     std::fprintf(stderr,"input:");
     for(size_t i=0;i<15 && i<before_n && i<bytes.size()-pos;++i)std::fprintf(stderr," %02x",unsigned(bytes[pos+i]));
     std::fprintf(stderr,"\n");
    }
    return 77;
   }
   if(!ok){++cursor;--n;++address;continue;}
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
