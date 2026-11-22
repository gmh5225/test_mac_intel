#include <capstone/capstone.h>
#include <dlfcn.h>
#include <algorithm>
#include <cstdio>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

struct Api {
  void *library;
  csh handle{};
  decltype(&cs_close) close;
  decltype(&cs_option) option;
  decltype(&cs_disasm_iter) iter;
  decltype(&cs_errno) error;
  decltype(&cs_disasm) batch;
  decltype(&cs_free) release;

  template<class F> F symbol(const char *name) {
    auto found = reinterpret_cast<F>(dlsym(library, name));
    if (!found) throw std::runtime_error(name);
    return found;
  }
  Api(const char *path, cs_mode mode) : library(dlopen(path, RTLD_NOW | RTLD_LOCAL)) {
    if (!library) throw std::runtime_error(dlerror());
    close = symbol<decltype(close)>("cs_close");
    option = symbol<decltype(option)>("cs_option");
    batch = symbol<decltype(batch)>("cs_disasm");
    release = symbol<decltype(release)>("cs_free");
    iter = symbol<decltype(iter)>("cs_disasm_iter");
    error = symbol<decltype(error)>("cs_errno");
    if (symbol<decltype(&cs_open)>("cs_open")(CS_ARCH_X86, mode, &handle))
      throw std::runtime_error("cs_open");
  }
  ~Api() { close(&handle); dlclose(library); }
};

int main(int argc, char **argv) {
  if (argc != 5) return 2;
  std::ifstream file(argv[3], std::ios::binary);
  if (!file) return 2;
  const std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), {});
  unsigned bits = std::stoul(argv[4]);
  cs_mode mode = bits == 16 ? CS_MODE_16 : bits == 32 ? CS_MODE_32 : CS_MODE_64;
  Api base(argv[1], mode), candidate(argv[2], mode);
  Api *apis[] = {&base, &candidate};
  struct Config { bool text, detail, att, skip, custom, reuse, every; };
  const Config configs[] = {
    {true,false,false,false,false,false,false}, {true,true,false,false,false,false,false},
    {true,true,false,true,false,true,false}, {true,true,true,false,false,true,false},
    {false,true,false,false,false,true,false}, {true,true,false,false,true,true,false},
    {true,true,false,false,false,false,true}, {true,false,false,true,false,true,true}};
  uint64_t attempts=0, batches=0, batch_records=0;
  for (unsigned ci=0; ci<sizeof(configs)/sizeof(*configs); ++ci) {
    auto cfg=configs[ci];
    cs_opt_mnem custom = {X86_INS_MOV, cfg.custom ? "test_mov" : nullptr};
    for (Api *a : apis)
      if (a->option(a->handle, CS_OPT_DETAIL, cfg.detail ? CS_OPT_ON : CS_OPT_OFF) ||
          a->option(a->handle, CS_OPT_TEXT, cfg.text ? CS_OPT_ON : CS_OPT_OFF) ||
          a->option(a->handle, CS_OPT_SYNTAX, cfg.att ? CS_OPT_SYNTAX_ATT : CS_OPT_SYNTAX_INTEL) ||
          a->option(a->handle, CS_OPT_SKIPDATA, cfg.skip ? CS_OPT_ON : CS_OPT_OFF) ||
          a->option(a->handle, CS_OPT_MNEMONIC, reinterpret_cast<size_t>(&custom)))
        throw std::runtime_error("cs_option");
    auto check_batch = [&](const uint8_t *start, size_t length, size_t count, uint64_t address) {
      cs_insn *items[2]{}; size_t used[2]; cs_err errors[2];
      for (unsigned side=0; side<2; ++side) {
        Api *a=apis[side];
        used[side]=a->batch(a->handle,start,length,address,count,&items[side]);
        errors[side]=a->error(a->handle);
      }
      if (used[0]!=used[1] || errors[0]!=errors[1] || bool(items[0])!=bool(items[1]))
        throw std::runtime_error("batch counts, error or allocation");
      for (size_t index=0; index<used[0]; ++index) {
        auto &left=items[0][index], &right=items[1][index];
        auto *d=right.detail;
        right.detail=left.detail;
        bool same=!std::memcmp(&left,&right,sizeof(left));
        right.detail=d;
        if (!same || bool(left.detail)!=bool(d) || (d && std::memcmp(left.detail,d,sizeof(*d))))
          throw std::runtime_error("batch instruction or detail mismatch");
      }
      for (unsigned side=0; side<2; ++side)
        apis[side]->release(items[side],used[side]);
      ++batches;
      batch_records+=used[0];
    };
    const uint8_t compare_and_moves[]={0xc5,0xf8,0xc2,0xc1,0x02,0x8b,0x03,0x90};
    check_batch(compare_and_moves,sizeof(compare_and_moves),0,0xfffffffeULL);
    const uint8_t clear[]={0xc5,0xf8,0x77,0xc4,0xe1,0x7c,0x77};
    check_batch(clear,sizeof(clear),0,0x2000);
    const size_t counts[]={0,1,7,64};
    for (size_t at=0; at<data.size(); at+=4093)
      for (size_t count : counts)
        check_batch(data.data()+at,std::min<size_t>(768,data.size()-at),count,0x100000+at);
    cs_insn insn[2]; cs_detail detail[2];
    size_t limit=cfg.every ? std::min<size_t>(16384,data.size()) : data.size();
    for (size_t off=0; off<limit;) {
      for (unsigned i=0; i<2; ++i) {
        if (!off || !cfg.reuse) {
          int seed=(int(off)^0xa5)&255;
          std::memset(&insn[i],seed,sizeof(cs_insn));
          std::memset(&detail[i],seed,sizeof(cs_detail));
          insn[i].is_alias=insn[i].usesAliasDetails=insn[i].illegal=false;
        }
        insn[i].detail=&detail[i];
      }
      const uint8_t *cur[2]={data.data()+off,data.data()+off};
      size_t n=cfg.every ? std::min<size_t>(off%17,data.size()-off) : data.size()-off;
      size_t left[2]={n,n};
      uint64_t address=cfg.every ? std::numeric_limits<uint64_t>::max()-7+off : 0x100000+off;
      uint64_t ip[2]={address,address}; bool ok[2]; cs_err err[2];
      for (unsigned i=0; i<2; ++i) {
        ok[i]=apis[i]->iter(apis[i]->handle,&cur[i],&left[i],&ip[i],&insn[i]);
        err[i]=apis[i]->error(apis[i]->handle);
        if(insn[i].detail!=&detail[i]) throw std::runtime_error("detail pointer");
        insn[i].detail=nullptr;
      }
      if(ok[0]!=ok[1] || left[0]!=left[1] || cur[0]!=cur[1] || ip[0]!=ip[1] ||
         err[0]!=err[1] || std::memcmp(insn,insn+1,sizeof(cs_insn)) ||
         std::memcmp(detail,detail+1,sizeof(cs_detail))) {
        std::fprintf(stderr,"public record mismatch at offset %zu config %u\n",off,ci);
        return 1;
      }
      if (ok[0] && (!insn[0].size || insn[0].size>n)) return 3;
      ++attempts;
      off += cfg.every || !ok[0] ? 1 : insn[0].size;
    }
  }
  std::printf("{\"complete_record_comparisons\":%llu,\"batch_calls\":%llu,\"batch_records\":%llu}\n",
              (unsigned long long)attempts,(unsigned long long)batches,(unsigned long long)batch_records);
}
