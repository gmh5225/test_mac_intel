#include <capstone/capstone.h>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
struct Receipt {
    uint64_t hashes[2] = {0x123456789abcdefULL,0xd6e8feb86659fd93ULL};
    uint64_t tried=0,ok=0;
    void add(uint64_t value) {
        hashes[0]=(hashes[0]^value)*0x9e3779b185ebca87ULL;
        hashes[1]=(hashes[1]+value)*0xd6e8feb86659fd93ULL+(hashes[1]>>32);
    }
    void bytes(const void *ptr,size_t n) {
        const auto *p=static_cast<const uint8_t *>(ptr);
        while (n>=8) {uint64_t v;std::memcpy(&v,p,8);add(v);p+=8;n-=8;}
        if(n){uint64_t v=0;std::memcpy(&v,p,n);add(v);}
    }
};
int main() {
    const size_t page=static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto *map=static_cast<uint8_t *>(mmap(nullptr,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0));
    if(map==MAP_FAILED || mprotect(map+page,page,PROT_NONE))return 1;
    const uint8_t prefixes[][3]={{},{0x67},{0x64},{0x66},{0xf0},{0xf2},{0x48},{0x64,0x67},{0x67,0x67},{0x64,0x65},{0x67,0x64,0x66}};
    const uint8_t counts[]={0,1,1,1,1,1,1,2,2,2,3};
    const uint8_t targeted[]={0xc2,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x66,0x67,0x9b,0xab,0x58,0x28,0xfe};
    for (auto mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64}) {
        csh h;if(cs_open(CS_ARCH_X86,mode,&h)!=CS_ERR_OK)return 2;
        cs_opt_mnem custom={X86_INS_ADD,"nondefault-add"};
        if(cs_option(h,CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&custom))!=CS_ERR_OK)return 3;
        for(int detail=0;detail<=1;++detail) {
            if(cs_option(h,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF)!=CS_ERR_OK)return 4;
            Receipt r;
            auto one=[&](const uint8_t *b,unsigned n,unsigned seed){
                auto *start=map+page-n;std::memcpy(start,b,n);const uint8_t *p=start;size_t left=n;uint64_t address=UINT64_MAX-7;
                cs_insn i;std::memset(&i,seed,sizeof(i));i.is_alias=i.usesAliasDetails=i.illegal=false;
                cs_detail d;std::memset(&d,seed^0xaa,sizeof(d));i.detail=detail?&d:nullptr;
                bool ok=cs_disasm_iter(h,&p,&left,&address,&i);r.tried++;r.ok+=ok;r.add(ok);r.add(p-start);r.add(left);r.add(address);r.add(cs_errno(h));
                if(i.detail!=(detail?&d:nullptr))return false;
                i.detail=nullptr;r.bytes(&i,sizeof(i));if(detail)r.bytes(&d,offsetof(cs_detail,x86)+sizeof(cs_x86));
                return true;
            };
            for(unsigned pass=0;pass<2;++pass) {
                const unsigned ops=pass?sizeof(targeted):256;
                const unsigned variants=pass?1024:16;
                for(unsigned j=0;j<ops;++j) for(unsigned m=0;m<8;++m) for(unsigned v=0;v<variants;++v) {
                    const unsigned opcode=pass?targeted[j]:j, pc=(v+j+m)%(sizeof(counts));
                    uint8_t bytes[24]={};const unsigned pref=counts[pc];std::memcpy(bytes,prefixes[pc],pref);
                    uint8_t *ev=bytes+pref;
                    ev[0]=0x62;ev[1]=static_cast<uint8_t>(((v*3+j)<<4)|((v&8)?8:0)|m);
                    ev[2]=static_cast<uint8_t>((((v>>2)+j)&15)<<3|((v&1)?0x80:0)|(v>>4&7));
                    ev[3]=static_cast<uint8_t>(v);ev[4]=static_cast<uint8_t>(opcode);ev[5]=static_cast<uint8_t>((v*41+j*17)&255);
                    for(unsigned k=6;k<17;++k)ev[k]=static_cast<uint8_t>(37*k+v);
                    const unsigned n=(v+j+m)%17;const unsigned seed=v+j*31+m;
                    if(!one(bytes,n,seed)||!one(bytes,16,seed))return 5;
                }
            }
            std::printf("%d %d %llu %llu %016llx %016llx\n",int(mode),detail,(unsigned long long)r.tried,(unsigned long long)r.ok,(unsigned long long)r.hashes[0],(unsigned long long)r.hashes[1]);
        }
        cs_close(&h);
    }
    return munmap(map,2*page)!=0;
}
