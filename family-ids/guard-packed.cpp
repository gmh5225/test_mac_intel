#define main existing_compare_main
#include "compare.cpp"
#undef main

int main(int argc,char **argv) {
  if(argc!=3)return 2;
  Api left(argv[1]),right(argv[2]);
  uint64_t trials=0,accepted=0;
  size_t pg=sysconf(_SC_PAGESIZE);
  auto *area=(uint8_t*)mmap(nullptr,pg*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
  check(area!=MAP_FAILED&&!mprotect(area+pg,pg,PROT_NONE),"pages");
  for(auto mode:{CS_MODE_32,CS_MODE_64,static_cast<cs_mode>(CS_MODE_64|CS_MODE_X86_AMD)}) {
    Session a(left,CS_ARCH_X86,mode),b(right,CS_ARCH_X86,mode);
    for(auto *s:{&a,&b})s->set(CS_OPT_TEXT,CS_OPT_OFF);
    for(unsigned op:{0x10,0x11,0x28,0x29})
    for(unsigned map:{0xf1,0x31,0xf2,0xf0})
    for(unsigned pp:{0x7c,0x7d,0x7e,0x7f,0xfc,0xfd,0xfe,0x74,0x78})
    for(unsigned ll:{0x08,0x28,0x48,0x68,0x88,0x09,0x58,0x00})
    for(unsigned mr=0;mr<256;++mr) {
      uint8_t form[17]={0x62,uint8_t(map),uint8_t(pp),uint8_t(ll),uint8_t(op),uint8_t(mr),uint8_t((mr>>3)%2?0x25:0x64),0x80,0x67,0x03,0xf3,0x66,0,0,0,0,0};
      const std::array<unsigned,6> sizes={5u,6u,7u,8u,10u,15u};
      for(unsigned n:sizes) {
        auto *data=area+pg-n;std::memcpy(data,form,n);
        const uint8_t *p[2]={data,data};size_t avail[2]={n,n};uint64_t ip[2]={0x100000,0x100000};cs_insn rec[2];cs_detail det[2];bool ok[2];
        for(unsigned i=0;i<2;++i){
          auto &s=i?b:a;std::memset(rec+i,0x5a,sizeof(*rec));std::memset(det+i,0x5a,sizeof(*det));
          rec[i].is_alias=rec[i].illegal=rec[i].usesAliasDetails=false;
          rec[i].detail=mr&1?det+i:nullptr;
          ok[i]=s.api.next(s.h,p+i,avail+i,ip+i,rec+i);
          check(rec[i].detail==(mr&1?det+i:nullptr),"detail storage");rec[i].detail=nullptr;
        }
        if(ok[0]!=ok[1]||p[0]!=p[1]||avail[0]!=avail[1]||ip[0]!=ip[1]||left.error(a.h)!=right.error(b.h)||
           std::memcmp(rec,rec+1,sizeof(*rec))||std::memcmp(det,det+1,sizeof(*det))) {
          std::fprintf(stderr,"different mode=%x opcode=%x prefix=%x/%x/%x modrm=%x len=%u\n",int(mode),op,map,pp,ll,mr,n);return 1;
        }
        ++trials;accepted+=ok[0];
      }
    }
  }
  std::printf("%llu %llu\n",(unsigned long long)trials,(unsigned long long)accepted);
  return munmap(area,pg*2)!=0;
}
