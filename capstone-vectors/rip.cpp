#define main old_bench_main
#include "rip-compare.cpp"
#undef main
#include <sys/mman.h>
#include <unistd.h>
#include <array>

static uint64_t cases,valid,queries;
int main(int argc,char **argv) {
    if(argc!=3)return 1;
    Api a(argv[1]),b(argv[2]);auto ordinary=a.sym<decltype(&cs_disasm_iter)>("cs_disasm_iter");
    auto fixed=b.next;size_t page=sysconf(_SC_PAGESIZE);
    auto map=(uint8_t*)mmap(nullptr,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(map==MAP_FAILED||mprotect(map+page,page,PROT_NONE))return 2;
    for(auto mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64})for(auto syntax : {CS_OPT_SYNTAX_INTEL,CS_OPT_SYNTAX_ATT})for(unsigned detail=0;detail!=2;++detail){
        Session l(a,CS_ARCH_X86,mode),r(b,CS_ARCH_X86,mode);
        for(Session *s:{&l,&r}){s->set(CS_OPT_SYNTAX,syntax);s->set(CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF);}
        auto verify=[&](const uint8_t *bytes,size_t n,uint64_t address){
            uint8_t *end=map+page,*buf=end-n;if(n)memcpy(buf,bytes,n);
            const uint8_t *x=buf,*y=buf;size_t nx=n,ny=n;uint64_t ip=address,jp=address;
            cs_insn u,v;cs_detail du,dv;memset(&u,0x5a,sizeof u);u.is_alias=u.illegal=u.usesAliasDetails=false;memcpy(&v,&u,sizeof u);
            memset(&du,0x5a,sizeof du);memcpy(&dv,&du,sizeof du);u.detail=&du;v.detail=&dv;
            bool ok=ordinary(l.h,&x,&nx,&ip,&u),got=fixed(r.h,&y,&ny,&jp,&v);
            check(u.detail==&du&&v.detail==&dv,"detail owner");
            u.detail=v.detail=nullptr;
            if(ok!=got || x!=y || nx!=ny || ip!=jp || a.error(l.h)!=b.error(r.h) || memcmp(&u,&v,sizeof(u)) || memcmp(&du,&dv,sizeof(du))) {
                fprintf(stderr,"mode=%u detail=%u addr=%" PRIx64 " bytes",unsigned(mode),detail,address);
                for(size_t i=0;i<n;++i)fprintf(stderr," %02x",buf[i]);
                fprintf(stderr," expected %s [%s] got %s [%s]\n",u.mnemonic,u.op_str,v.mnemonic,v.op_str);exit(3);
            }
            if(ok && detail){u.detail=&du;v.detail=&dv;cs_regs ar{},aw{},br{},bw{};uint8_t nr=0,nw=0,mr=0,mw=0;
                if(a.regs(l.h,&u,ar,&nr,aw,&nw)!=b.regs(r.h,&v,br,&mr,bw,&mw)||nr!=mr||nw!=mw||memcmp(ar,br,sizeof ar)||memcmp(aw,bw,sizeof aw))exit(4);
                ++queries;}
            ++cases;valid+=ok;
        };
        for (unsigned mr=0;mr<256;++mr) for(unsigned ll=0;ll<4;++ll)
        for(unsigned op : {0x10u,0x11u,0x28u,0x29u,0x6fu,0x7fu}) {
            for(unsigned lead : {0xf1u,0x71u,0xb1u,0xd1u,0xe1u,0xa1u}) {
                for(unsigned flags : {0x7cu,0x7du,0x7eu,0x7fu,0xfcu,0xfdu,0xfeu,0xffu}){
                    const uint8_t sib=uint8_t((mr%3==0)?0x24:(mr%3==1)?0xd5:0x9c);
                    uint8_t code[]={0x62,uint8_t(lead),uint8_t(flags),uint8_t(8+32*ll),
                                    uint8_t(op),uint8_t(mr),sib,0x80,0x7f,0xff,0xe5};
                    verify(code,sizeof code,0xf042);
                    if(lead==0xf1 && flags==0x7c && (mr&7)==4)
                        for(unsigned s=0;s!=256;++s){
                            code[6]=uint8_t(s);
                            verify(code,sizeof code,0x4020);
                        }
                    if(lead==0xf1 && flags==0x7c && (mr&0x38)==0)
                        for(size_t n=0;n<sizeof code;++n)verify(code,n,0x6000);
                }
            }
        }
    }
    munmap(map,page*2);printf("{\"cases\":%" PRIu64 ",\"accepted\":%" PRIu64 ",\"register_queries\":%" PRIu64 "}\n",cases,valid,queries);
    return 0;
}
