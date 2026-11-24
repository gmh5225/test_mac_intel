#define main prior_driver
#include "compare.cpp"
#undef main

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  Api base(argv[1]), candidate(argv[2]);
  uint64_t inputs=0, accepted=0, declined=0;
  for (cs_mode mode : {CS_MODE_16, (cs_mode)(CS_MODE_16 | CS_MODE_X86_AMD), (cs_mode)(CS_MODE_16 | CS_MODE_X86_INTEL)}) {
    Session a(base,CS_ARCH_X86,mode), b(candidate,CS_ARCH_X86,mode);
    for (unsigned option=0;option<4;++option) {
      const bool details=option==1 || option==2;
      for (Session *s : {&a,&b}) {
        s->set(CS_OPT_DETAIL,details?CS_OPT_ON:CS_OPT_OFF);
        s->set(CS_OPT_SYNTAX,option==2?CS_OPT_SYNTAX_ATT:option==3?CS_OPT_SYNTAX_MASM:CS_OPT_SYNTAX_INTEL);
        s->set(CS_OPT_TEXT,option==3?CS_OPT_OFF:CS_OPT_ON);
        s->set(CS_OPT_UNSIGNED,option==4?CS_OPT_ON:CS_OPT_OFF);
        cs_opt_mnem mnemonic{X86_INS_OR,option==5?"custom_mask":nullptr};
        s->set(CS_OPT_MNEMONIC,(size_t)&mnemonic);
      }
      auto check_record=[&](const std::vector<uint8_t>&bytes,size_t length) {
        const uint8_t *u=bytes.data(),*v=u; size_t left=length,right=length;uint64_t ip=0x180003214,pc=ip;
        cs_insn l,r;cs_detail d,e;
        memset(&l,0x55,sizeof l);l.illegal=l.is_alias=l.usesAliasDetails=false;r=l;
        memset(&d,0x5a,sizeof d);memcpy(&e,&d,sizeof d);
        l.detail=details?&d:nullptr;r.detail=details?&e:nullptr;
        bool l_ok=base.next(a.h,&u,&left,&ip,&l),r_ok=candidate.next(b.h,&v,&right,&pc,&r);
        l.detail=r.detail=nullptr;
        if (l_ok!=r_ok || u!=v || left!=right || ip!=pc || base.error(a.h)!=candidate.error(b.h) || memcmp(&l,&r,sizeof l) || memcmp(&d,&e,sizeof d)) {
          fprintf(stderr,"scalar lookup differs mode=%u option=%u len=%zu bytes=",(unsigned)mode,option,length);
          for(unsigned char byte:bytes)fprintf(stderr,"%02x",byte);
          fprintf(stderr," base='%s %s' candidate='%s %s'\n",l.mnemonic,l.op_str,r.mnemonic,r.op_str);exit(3);
        }
        ++inputs;accepted+=l_ok;declined+=!l_ok;
      };
      for (const auto &prefix : std::vector<std::vector<uint8_t>>{{},{0x66},{0x67},{0x66,0x67},{0x2e},{0xf0},{0xf3},{0xf2,0x66}}) {
        for (unsigned op=0; op<256; ++op) for (unsigned mr=0; mr<256; ++mr) {
          if (prefix.size() && prefix.front()!=0x66 && prefix.front()!=0x67 && (mr&7))continue;
          std::vector<uint8_t> bytes=prefix;
          bytes.push_back(op);bytes.push_back(mr);
          for(unsigned i=0;i<9;++i)bytes.push_back((op*17+mr*13+i*43)&255);
          check_record(bytes,bytes.size());
          for(unsigned len=0;len<=prefix.size()+7;++len)check_record(bytes,len);
        }
      }
    }
  }
  if (!declined || !accepted) return 4;
  printf("{\"inputs\":%" PRIu64 ",\"accepted\":%" PRIu64 ",\"rejected\":%" PRIu64 "}\n",inputs,accepted,declined);
}
