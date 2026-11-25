#define main existing_comparison_main
#include "trial-compare.cpp"
#undef main

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  Api reference(argv[1]), proposed(argv[2]);
  uint64_t trials=0, accepted=0;
  for (unsigned width : {unsigned(CS_MODE_MIPS32), unsigned(CS_MODE_MIPS64)})
    for (unsigned endian : {0u, unsigned(CS_MODE_BIG_ENDIAN)})
     for(unsigned syntax=0;syntax<4;++syntax) for (unsigned opt=0;opt<4;++opt) {
      cs_mode mode=static_cast<cs_mode>(width|endian);
      Session a(reference,CS_ARCH_MIPS,mode), b(proposed,CS_ARCH_MIPS,mode);
      for (auto *session : {&a, &b}) {
        session->set(CS_OPT_SYNTAX,(syntax&1 ? CS_OPT_SYNTAX_NOREGNAME : 0)|(syntax&2 ? CS_OPT_SYNTAX_NO_DOLLAR : 0));
        session->set(CS_OPT_TEXT,opt ? CS_OPT_ON : CS_OPT_OFF);
        session->set(CS_OPT_DETAIL,opt<2 ? CS_OPT_OFF : (opt==2 ? unsigned(CS_OPT_ON) : unsigned(CS_OPT_ON)|unsigned(CS_OPT_DETAIL_REAL)));
      }
      for (uint32_t major=0;major<64;++major)
        for (uint32_t rs=0;rs<32;++rs)
          for (uint32_t rt=0;rt<32;++rt)
            for (uint32_t imm : {0u,1u,0x7fffu,0x8000u,0xffffu}) {
              uint32_t word=(major<<26)|(rs<<21)|(rt<<16)|imm;
              uint8_t bytes[4];
              for (unsigned i=0;i<4;++i) bytes[endian ? 3-i : i]=uint8_t(word>>(8*i));
              uint64_t ip=0xfffc,pc=ip;size_t na=4,nb=4;
              const uint8_t *pa=bytes,*pb=bytes;cs_insn left{},right{};
              memset(left.bytes,0xa5,sizeof(left.bytes));memset(left.mnemonic,0xa5,sizeof(left.mnemonic));memset(left.op_str,0x5a,sizeof(left.op_str));right=left;
              cs_detail da{},db{}; left.detail=opt>=2 ? &da : nullptr; right.detail=opt>=2 ? &db : nullptr;
              bool ok=a.api.next(a.h,&pa,&na,&ip,&left),same=b.api.next(b.h,&pb,&nb,&pc,&right);
              if (left.detail!=(opt>=2 ? &da : nullptr) || right.detail!=(opt>=2 ? &db : nullptr) || memcmp(&da,&db,sizeof(da))) return 7;
              left.detail=right.detail=nullptr;
              if (ok!=same||na!=nb||pa!=pb||pc!=ip||memcmp(&left,&right,sizeof(left))||a.api.error(a.h)!=b.api.error(b.h)) {
                fprintf(stderr,"mode=%x word=%08x accepted=%d/%d id=%u/%u size=%u/%u\n",unsigned(mode),word,ok,same,left.id,right.id,left.size,right.size);
                return 1;
              }
              ++trials; accepted+=ok;
            }
    }
  printf("{\"trials\":%" PRIu64 ",\"accepted\":%" PRIu64 "}\n",trials,accepted);
}
