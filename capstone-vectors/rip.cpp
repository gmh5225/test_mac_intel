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
        for (unsigned prefix=0;prefix!=24;++prefix) for(unsigned mr=0;mr!=256;++mr) {
            for(uint32_t disp : {0u,1u,9u,10u,0x7fu,0xffffff81u,0xffffff80u,0x7fffffffu,0x80000000u,0xfffffffeu,0x80010002u}) {
                uint8_t code[16]={};unsigned n=0;
                if(prefix!=0)code[n++]=prefix<=16 ? uint8_t(0x3f+prefix) :
                    std::array<uint8_t,7>{0x66,0x67,0xf0,0x64,0x2e,0xf2,0xff}[prefix-17];
                code[n++]=0xff;code[n++]=uint8_t(mr);for(unsigned k=0;k!=4;++k)code[n++]=uint8_t(disp>>(8*k));
                verify(code,sizeof code,0xfffff073);
                if((mr==0x15||mr==0x25||mr==0x14||mr==0x24) && disp==0x80010002u)
                    for(unsigned k=0;k<=n;++k)verify(code,k,0x4000);
            }
        }
    }
    munmap(map,page*2);printf("{\"cases\":%" PRIu64 ",\"accepted\":%" PRIu64 ",\"register_queries\":%" PRIu64 "}\n",cases,valid,queries);
    return 0;
}
