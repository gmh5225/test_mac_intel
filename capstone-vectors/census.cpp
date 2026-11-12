#include <capstone/capstone.h>
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <vector>
extern "C" bool census_output(csh h, const uint8_t *p, size_t n, cs_insn *i);
int main(int argc, char **argv) {
  if (argc != 4) return 1;
  unsigned bits = std::stoul(argv[3]);
  csh h;
  if (cs_open(CS_ARCH_X86,bits==32 ? CS_MODE_32 : CS_MODE_64,&h) ||
      cs_option(h,CS_OPT_DETAIL,CS_OPT_ON)) return 2;
  auto *i = cs_malloc(h);
  std::ifstream file(argv[1],std::ios::binary),spans(argv[2]);
  const std::vector<uint8_t> data{std::istreambuf_iterator<char>(file),{}};
  std::map<std::string,uint64_t> counts;
  uint64_t off,n,ip;
  while (spans >> off >> n >> ip) {
    if(off > data.size() || n > data.size()-off) return 3;
    const auto *p = data.data()+off;size_t left=n;
    while(left) {
      auto *start=p;size_t before=left;
      if(!cs_disasm_iter(h,&p,&left,&ip,i)) break;
      const auto &x=i->detail->x86;
      std::ostringstream key;
      key << i->mnemonic;
      for(unsigned j=0;j<x.op_count;++j) {
        const auto &op=x.operands[j];
        key << (op.type==X86_OP_REG?"/r":op.type==X86_OP_IMM?"/i":op.type==X86_OP_MEM?"/m":"/?") << unsigned(op.size);
        if(op.type==X86_OP_MEM) key<<(op.mem.base?"B":"-")<<(op.mem.index?"I":"-")<<unsigned(x.encoding.disp_size);
      }
      ++counts[(census_output(h,start,before,i)?"hit ":"miss ")+key.str()];
    }
  }
  for(const auto &[k,v]:counts) std::cout << v << ' ' << k << '\n';
  cs_free(i,1);cs_close(&h);
}
