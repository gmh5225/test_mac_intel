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
          fprintf(stderr,"memory ALU differs mode=%u option=%u len=%zu bytes=",(unsigned)mode,option,length);
          for(unsigned char byte:bytes)fprintf(stderr,"%02x",byte);
          fprintf(stderr," base='%s %s' candidate='%s %s'\n",l.mnemonic,l.op_str,r.mnemonic,r.op_str);exit(3);
        }
        ++inputs;accepted+=l_ok;declined+=!l_ok;
      };
      for (auto prefix : std::vector<std::vector<uint8_t>>{{},{0x66},{0x67},{0x64},{0x40},{0x48},{0xf0}}) {
        for(unsigned op:{0x80u,0x81u,0x83u}) for(unsigned mr=0;mr<256;++mr) {
          for(unsigned address : {0x04u,0x24u,0x25u,0x59u,0xedu}) {
            if((mr&7)!=4 && address!=0x24)continue;
            for(uint32_t imm:{0u,1u,9u,10u,127u,128u,254u,255u,0x7fffffffu,0x80000000u,0xffffffffu}) {
              std::vector<uint8_t> v=prefix;v.insert(v.end(),{(uint8_t)op,(uint8_t)mr});
              const unsigned mod=mr>>6;const bool sib=mod!=3&&(mr&7)==4;
              if(sib)v.push_back((uint8_t)address);
              const unsigned disp=mod==1?1:(mod==2||(!mod&&((mr&7)==5||(sib&&(address&7)==5))))?4:0;
              for(unsigned byte=0;byte<disp;++byte)v.push_back((uint8_t)(0xff-byte));
              for(unsigned byte=0;byte<(op==0x81?4:1);++byte)v.push_back((uint8_t)(imm>>(byte*8)));
              check_record(v,v.size());
              if(imm==128 && (mr&3)==0)for(size_t n=0;n<v.size();++n)check_record(v,n);
            }
          }
        }
      }
    }
  }
  if (!declined || !accepted) return 4;
  printf("{\"inputs\":%" PRIu64 ",\"accepted\":%" PRIu64 ",\"rejected\":%" PRIu64 "}\n",inputs,accepted,declined);
}
