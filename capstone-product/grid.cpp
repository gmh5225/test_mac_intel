#define main prior_driver
#include "compare.cpp"
#undef main

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  Api base(argv[1]), candidate(argv[2]);
  uint64_t inputs=0, accepted=0, declined=0;
  for (cs_mode mode : {CS_MODE_16, CS_MODE_32, CS_MODE_64}) {
    Session a(base,CS_ARCH_X86,mode), b(candidate,CS_ARCH_X86,mode);
    for (unsigned option=0;option<6;++option) {
      const bool details=option!=0;
      for (Session *s : {&a,&b}) {
        s->set(CS_OPT_DETAIL,details?CS_OPT_ON:CS_OPT_OFF);
        s->set(CS_OPT_SYNTAX,option==2?CS_OPT_SYNTAX_ATT:option==3?CS_OPT_SYNTAX_MASM:CS_OPT_SYNTAX_INTEL);
        s->set(CS_OPT_UNSIGNED,option==4?CS_OPT_ON:CS_OPT_OFF);
        cs_opt_mnem mnemonic{X86_INS_CALL,option==5?"custom_mask":nullptr};
        s->set(CS_OPT_MNEMONIC,(size_t)&mnemonic);
      }
      auto check_record=[&](const std::vector<uint8_t>&bytes,size_t length,uint64_t address) {
        const uint8_t *u=bytes.data(),*v=u; size_t left=length,right=length;uint64_t ip=address,pc=ip;
        cs_insn l,r;cs_detail d,e;
        memset(&l,0x55,sizeof l);l.illegal=l.is_alias=l.usesAliasDetails=false;r=l;
        memset(&d,0x5a,sizeof d);memcpy(&e,&d,sizeof d);
        l.detail=details?&d:nullptr;r.detail=details?&e:nullptr;
        bool l_ok=base.next(a.h,&u,&left,&ip,&l),r_ok=candidate.next(b.h,&v,&right,&pc,&r);
        l.detail=r.detail=nullptr;
        if (l_ok!=r_ok || u!=v || left!=right || ip!=pc || base.error(a.h)!=candidate.error(b.h) || memcmp(&l,&r,sizeof l) || memcmp(&d,&e,sizeof d)) {
          fprintf(stderr,"address tuple differs mode=%u option=%u len=%zu bytes=",(unsigned)mode,option,length);
          for(unsigned char byte:bytes)fprintf(stderr,"%02x",byte);
          fprintf(stderr," base='%s %s' candidate='%s %s'\n",l.mnemonic,l.op_str,r.mnemonic,r.op_str);exit(3);
        }
        ++inputs;accepted+=l_ok;declined+=!l_ok;
      };
      const std::vector<std::vector<uint8_t>> variants = {
        {0x8b}, {0x67,0x8d}, {0x64,0x2b}, {0x65,0x67,0x8b}, {0x66,0x0f,0x6f},
        {0x48,0x8d}, {0x4f,0x89}, {0xc5,0xfc,0x10}, {0xc4,0xe2,0x7d,0x92},
        {0x62,0xf2,0x7d,0x49,0x92}, {0x62,0xf1,0x7c,0x48,0x10}, {0xd5,0x18,0x8b}
      };
      for (const auto &opcode : variants) {
        for(unsigned mr=0;mr<256;++mr) {
          for(unsigned sib : {0u,0x24u,0x25u,0x64u,0x85u,0xbdu,0xe4u,0xffu}) {
            auto bytes=opcode;
            bytes.insert(bytes.end(),{(uint8_t)mr,(uint8_t)sib,0x80,0xff,0xff,0x7f,0});
            for(size_t n=0;n<=bytes.size();++n)check_record(bytes,n,0xfffffffdu);
          }
        }
      }
    }
  }
  if (!declined || !accepted) return 4;
  printf("{\"inputs\":%" PRIu64 ",\"accepted\":%" PRIu64 ",\"rejected\":%" PRIu64 "}\n",inputs,accepted,declined);
}
