#include <array>
#define main prior_driver
#include "trial-compare.cpp"
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
        cs_opt_mnem mnemonic{X86_INS_MOV,option==5?"custom_mask":nullptr};
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
          fprintf(stderr,"relative encoding differs mode=%u option=%u len=%zu bytes=",(unsigned)mode,option,length);
          for(unsigned char byte:bytes)fprintf(stderr,"%02x",byte);
          fprintf(stderr," base='%s %s' candidate='%s %s'\n",l.mnemonic,l.op_str,r.mnemonic,r.op_str);exit(3);
        }
        ++inputs;accepted+=l_ok;declined+=!l_ok;
      };
      for (unsigned slot=0;slot<34;++slot) {
        bool escaped=slot>=18;
        unsigned opcode=slot<16?0x70+slot:slot==16?0xeb:slot==17?0xe9:0x80+slot-18;
        for (unsigned raw=0;raw<256;++raw) {
          for(unsigned pre:{0u,0x66u,0x67u,0x6766u}){
            if(pre && raw%31)continue;
            std::vector<uint8_t> bytes;
            if(pre>>8)bytes.push_back(pre>>8);
            if(pre)bytes.push_back(pre&255);
            if(escaped)bytes.push_back(0x0f);
            bytes.insert(bytes.end(),{uint8_t(opcode),uint8_t(raw),uint8_t(raw^0x80),0x55,0xaa});
            for (uint64_t ip : std::array<uint64_t,10>{0,7,15,0xfffd,0xffff,0x10000,0x10008,0xfffffffd,UINT64_MAX-1,UINT64_MAX}) {
              for(size_t n=0;n<=bytes.size();++n)check_record(bytes,n,ip);
            }
          }
        }
      }
    }
  }
  if (!declined || !accepted) return 4;
  printf("%" PRIu64 " %" PRIu64 "\n",inputs,accepted);
}
