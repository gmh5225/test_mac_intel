#define main prior_benchmark
#include "trial-compare.cpp"
#undef main

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  Api reference(argv[1]), candidate(argv[2]);
  const size_t page = sysconf(_SC_PAGESIZE);
  auto *buffer = static_cast<uint8_t *>(mmap(nullptr, 2 * page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0));
  check(buffer != MAP_FAILED && !mprotect(buffer + page, page, PROT_NONE), "guard pages");
  uint64_t calls = 0, accepted = 0;
  const unsigned addresses[] = {0, 1, 4, 5, 7, 0x40, 0x44, 0x45, 0x47, 0x80, 0x84, 0x85, 0x87, 0xc0, 0xff};
  for (auto width : {CS_MODE_16, CS_MODE_32, CS_MODE_64}) {
    Session base(reference, CS_ARCH_X86, width), trial(candidate, CS_ARCH_X86, width);
    cs_opt_mnem canonical{X86_INS_UD2, "ud2"}; base.set(CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&canonical));
    for (unsigned option = 0; option < 8; ++option) {
      for (auto *s : {&base, &trial}) {
        s->set(CS_OPT_DETAIL, (option & 1) ? CS_OPT_ON : CS_OPT_OFF);
        s->set(CS_OPT_UNSIGNED, (option & 2) ? CS_OPT_ON : CS_OPT_OFF);
        s->set(CS_OPT_TEXT, (option & 4) ? CS_OPT_OFF : CS_OPT_ON);
      }
      const bool full = width == CS_MODE_64 && option <= 1;
      for (unsigned map = 0; map < 5; ++map)
        for (unsigned op = 0; op != 256; ++op)
          for (unsigned wp = 0; wp != 8; ++wp)
            for (unsigned ll = 0; ll != 4; ++ll)
              for (unsigned shape : addresses) {
                const unsigned seed = (map + 3*op + 5*wp + 7*ll + shape);
                if (!full && (seed & 15)) continue;
                const unsigned ext = (seed & 15) << 4, vv = (seed >> 1) & 31;
                const unsigned mr = shape | (((seed >> 3) & 7) << 3);
                const unsigned prefix = map | ext;
                const unsigned flags = ((wp & 4) << 5) | ((~vv & 15)<<3) | 4 | (wp & 3);
                const unsigned control = (ll << 5) | ((~vv & 16) >> 1);
                for (unsigned invalid : {0u, 1u, 2u, 3u, 4u}) {
                  if (invalid && (seed & 31)) continue;
                  uint8_t bytes[] = {0x62,uint8_t(prefix),uint8_t(flags),uint8_t(control),uint8_t(op),uint8_t(mr),uint8_t(seed),0x80,0xff,0x7f,0x90,0xb1};
                  if(invalid==1)bytes[2]^=4;
                  if(invalid==2)bytes[3]|=0x80;
                  if(invalid==3)bytes[3]|=0x10;
                  if(invalid==4)bytes[3]|=7;
                  unsigned mod=mr>>6, rm=mr&7, sib=(rm==4 && mod!=3);
                  const unsigned disp=mod==2 || (!mod && (rm==5 || (sib && (bytes[6]&7)==5)))?4:mod==1;
                  const unsigned length=6+sib+disp;
                  for(unsigned n=0;n<=length+1;++n) {
                    if(n!=length && n!=length+1 && (seed&7))continue;
                    auto *at=buffer+page-n;std::memcpy(at,bytes,n);
                    const uint8_t *cursor[2]={at,at};size_t size[2]={n,n};
                    uint64_t addr[2]={UINT64_MAX-2,UINT64_MAX-2};cs_insn i[2];cs_detail d[2];bool ok[2];
                    for(unsigned k=0;k<2;++k) {
                      Session &s=k?trial:base;
                      std::memset(i+k,0xa5,sizeof(*i));std::memset(d+k,0x5a,sizeof(*d));
                      i[k].illegal=i[k].is_alias=i[k].usesAliasDetails=false;
                      auto *owner=(option&1)?d+k:nullptr;i[k].detail=owner;
                      ok[k]=s.api.next(s.h,cursor+k,size+k,addr+k,i+k);
                      check(i[k].detail==owner,"detail ownership");i[k].detail=nullptr;
                    }
                    if (ok[0]!=ok[1] || cursor[0]!=cursor[1] || size[0]!=size[1] || addr[0]!=addr[1] || reference.error(base.h)!=candidate.error(trial.h) ||
                        std::memcmp(i,i+1,sizeof(*i)) || std::memcmp(d,d+1,sizeof(*d))) {
                      std::fprintf(stderr,"EVEX mode=%u option=%u bytes=",unsigned(width),option);
                      for(unsigned j=0;j<n;++j)std::fprintf(stderr,"%02x",bytes[j]);
                      std::fprintf(stderr," source=[%s %s], candidate=[%s %s]\n",i[0].mnemonic,i[0].op_str,i[1].mnemonic,i[1].op_str);
                      return 3;
                    }
                    ++calls;accepted+=ok[0];
                  }
                }
              }
    }
  }
  std::printf("%llu %llu\n",(unsigned long long)calls,(unsigned long long)accepted);
  return munmap(buffer,2*page)!=0;
}
