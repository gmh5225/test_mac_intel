#define main prior_driver
#include "trial-compare.cpp"
#undef main

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  Api base(argv[1]), candidate(argv[2]);
  const size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  auto *pages = static_cast<uint8_t *>(mmap(nullptr, page_size * 3, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0));
  check(pages != MAP_FAILED && mprotect(pages + page_size,page_size,PROT_READ | PROT_WRITE) == 0, "guard pages");
  uint64_t inputs=0, accepted=0, declined=0;
  for (cs_mode mode : {CS_MODE_16, CS_MODE_32, CS_MODE_64}) {
    Session a(base,CS_ARCH_X86,mode), b(candidate,CS_ARCH_X86,mode);
    for (unsigned option=0;option<6;++option) {
      const bool details=option!=0;
      for (Session *s : {&a,&b}) {
        s->set(CS_OPT_DETAIL,details?CS_OPT_ON:CS_OPT_OFF);
        s->set(CS_OPT_SYNTAX,option==2?CS_OPT_SYNTAX_ATT:option==3?CS_OPT_SYNTAX_MASM:CS_OPT_SYNTAX_INTEL);
        s->set(CS_OPT_UNSIGNED,option==4?CS_OPT_ON:CS_OPT_OFF);
        cs_opt_mnem mnemonic{X86_INS_VZEROUPPER,option==5?"custom_mask":nullptr};
        s->set(CS_OPT_MNEMONIC,(size_t)&mnemonic);
      }
      auto check_record=[&](const std::vector<uint8_t>&bytes,size_t length,uint64_t address) {
        for (bool end : {false,true}) {
        uint8_t *at = pages + (end ? 2 * page_size - length : page_size);
        if (length) std::memcpy(at,bytes.data(),length);
        const uint8_t *u=at,*v=u; size_t left=length,right=length;uint64_t ip=address,pc=ip;
        cs_insn l,r;cs_detail d,e;
        memset(&l,0x55,sizeof l);l.illegal=l.is_alias=l.usesAliasDetails=false;r=l;
        memset(&d,0x5a,sizeof d);memcpy(&e,&d,sizeof d);
        l.detail=details?&d:nullptr;r.detail=details?&e:nullptr;
        bool l_ok=base.next(a.h,&u,&left,&ip,&l),r_ok=candidate.next(b.h,&v,&right,&pc,&r);
        l.detail=r.detail=nullptr;
        if (l_ok!=r_ok || u!=v || left!=right || ip!=pc || base.error(a.h)!=candidate.error(b.h) || memcmp(&l,&r,sizeof l) || memcmp(&d,&e,sizeof d)) {
          fprintf(stderr,"vector encoding differs mode=%u option=%u len=%zu bytes=",(unsigned)mode,option,length);
          for(unsigned char byte:bytes)fprintf(stderr,"%02x",byte);
          fprintf(stderr," base='%s %s' candidate='%s %s'\n",l.mnemonic,l.op_str,r.mnemonic,r.op_str);exit(3);
        }
        ++inputs;accepted+=l_ok;declined+=!l_ok;
        }
      };
      const std::vector<std::vector<uint8_t>> prefixes = {
        {0xc5,0xf9},{0xc5,0xfd},{0xc5,0xf1},{0xc4,0xe2,0x7d},{0xc4,0xe3,0x79},
        {0xc4,0x42,0x31},{0x62,0xf1,0x7d,0x48},{0x62,0x72,0xfd,0x28},{0x62,0xf3,0x7d,0x48},
        {0x66,0x0f},{0x66,0x41,0x0f},{0x66,0x0f,0x38},{0x66,0x4e,0x0f,0x38}
      };
      for (const auto &prefix : prefixes) for (unsigned opcode : {0x00u,0x21u,0x38u,0x48u,0x58u,0x6fu,0x70u,0x71u,0x72u,0x73u,0x76u,0xefu})
        for (unsigned mr : {0x04u,0x45u,0xc0u,0xc8u,0xd0u,0xe1u,0xf2u,0xffu}) {
          auto bytes = prefix;
          bytes.insert(bytes.end(),{uint8_t(opcode),uint8_t(mr),0x9f});
          for (size_t n=0;n<=bytes.size();++n) check_record(bytes,n,0xfffffffd);
        }
      for (unsigned rex : {0u,0x40u,0x43u,0x4cu,0x4fu}) {
        for (bool map38 : {false,true}) {
          for (unsigned opcode=map38?0:0x70;opcode<=(map38?255u:0x73u);++opcode) {
            for (unsigned mr : {0x05u,0x44u,0x80u,0xc0u,0xc9u,0xd1u,0xdau,0xe3u,0xecu,0xf5u,0xffu}) {
              std::vector<uint8_t> bytes={0x66};
              if (rex) bytes.push_back(uint8_t(rex));
              bytes.push_back(0x0f);
              if (map38) bytes.push_back(0x38);
              bytes.push_back(uint8_t(opcode));bytes.push_back(uint8_t(mr));
              bytes.push_back(0x96);
              for (size_t n=0;n<=bytes.size();++n) check_record(bytes,n,0xfffffffd);
            }
          }
        }
      }
    }
  }
  munmap(pages,3*page_size);
  if (!declined || !accepted) return 4;
  printf("{\"inputs\":%" PRIu64 ",\"accepted\":%" PRIu64 ",\"rejected\":%" PRIu64 "}\n",inputs,accepted,declined);
}
