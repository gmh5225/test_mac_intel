#include <capstone/capstone.h>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif
extern "C" bool observed_bare(const uint8_t *, size_t, bool);
extern "C" bool X86_disasmIterText(csh, const uint8_t **, size_t *, uint64_t *, cs_insn *);
int main(int argc, char **)
{
    const bool candidate = argc == 2;
#ifdef _WIN32
    SYSTEM_INFO system; GetSystemInfo(&system);
    size_t page = system.dwPageSize;
    auto *area = static_cast<uint8_t *>(VirtualAlloc(nullptr, 2*page, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE));
    DWORD old;
    if (!area || !VirtualProtect(area+page, page, PAGE_NOACCESS, &old)) return 2;
#else
    size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto *area = static_cast<uint8_t *>(mmap(nullptr, page*2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0));
    if (area == MAP_FAILED || mprotect(area+page, page, PROT_NONE)) return 2;
#endif
    unsigned long long trials=0, hits[2]={};
    for (unsigned wide : {0,1}) for (unsigned detail : {0,1}) {
        csh target=0, normal=0;
        auto mode = wide ? CS_MODE_64 : CS_MODE_32;
        cs_opt_mnem m{X86_INS_UD2, "ud2"};
        if (cs_open(CS_ARCH_X86, mode, &target) || cs_open(CS_ARCH_X86, mode, &normal) ||
            cs_option(normal, CS_OPT_MNEMONIC, reinterpret_cast<uintptr_t>(&m))) return 3;
        if (detail && (cs_option(normal,CS_OPT_DETAIL,CS_OPT_ON) || cs_option(target,CS_OPT_DETAIL,CS_OPT_ON))) return 4;
        auto check = [&](const std::array<uint8_t,7>& bytes, unsigned n) {
            auto *input=area+page-n;
            std::memcpy(input,bytes.data(),n);
            const uint8_t *a=input,*b=input;
            size_t na=n, nb=n; uint64_t ip=0xfffffffcu, ref_ip=ip;
            cs_insn got,ref; cs_detail dg,dr;
            std::memset(&got,0xa5,sizeof(got));std::memset(&dg,0xa5,sizeof(dg));
            got.illegal=false;got.is_alias=false;got.usesAliasDetails=false;got.alias_id=0;
            std::memcpy(&ref,&got,sizeof(ref));std::memcpy(&dr,&dg,sizeof(dr));
            got.detail=detail?&dg:nullptr;ref.detail=detail?&dr:nullptr;
            bool hit=observed_bare(input,n,wide);
            bool accepted=X86_disasmIterText(target,&a,&na,&ip,&got);
            bool expected=cs_disasm_iter(normal,&b,&nb,&ref_ip,&ref);
            if (got.detail!=(detail?&dg:nullptr) || ref.detail!=(detail?&dr:nullptr)) return false;
            got.detail=ref.detail;
            if (accepted!=expected || (hit&&!accepted) || a!=b || na!=nb || ip!=ref_ip ||
                std::memcmp(&got,&ref,sizeof(ref)) || std::memcmp(&dg,&dr,sizeof(dr))) {
                std::fprintf(stderr,"mode=%u detail=%u n=%u hit=%u ok=%u/%u code=",wide,detail,n,hit,accepted,expected);
                for(unsigned i=0;i<n;++i)std::fprintf(stderr,"%02x",input[i]);
                std::fprintf(stderr," size=%u/%u id=%u/%u\n",got.size,ref.size,got.id,ref.id);
                return false;
            }
            ++trials;hits[wide]+=hit;
            return true;
        };
        for (unsigned op=0;op<256;++op) for (unsigned seed=0;seed<128;++seed) {
            for (unsigned prefix : {2,3}) {
                std::array<uint8_t,7> v{};
                v[0]=prefix==2?0xc5:0xc4;
                v[1]=uint8_t((seed&7)<<5 | (seed<96?1:(seed>>3)&3));
                unsigned pp=seed<96?0:(seed>>3)&3;
                v[prefix-1]=uint8_t(((seed*53)&0xfc)|pp);
                v[prefix]=uint8_t(op);v[prefix+1]=uint8_t(((seed&15)?0xc0:0)|((seed*7+op)&63));
                v[prefix+2]=uint8_t(op+13*seed);
                for (unsigned n=0;n<=prefix+3;++n)if(!check(v,n))return 5;
            }
        }
        if (wide && detail) {
            // Enumerate every register tuple and both index-extension encodings
            // for rows admitted by the new map. Immediate aliases are independently
            // checked at all 256 values in the canonical table generator.
            for (unsigned op=0;op<256;++op)for(unsigned wl=0;wl<4;++wl) {
                std::array<uint8_t,7> v={0xc4,0xe1,uint8_t((wl>>1)<<7 | 0x68 | ((wl&1)<<2)),uint8_t(op),0xd9,0x80,0};
                if (!observed_bare(v.data(),6,true)) continue;
                for (unsigned k=0;k<8192;++k) {
                    v[1]=uint8_t(((k>>10)^7)<<5|1);v[2]=uint8_t((wl>>1)<<7 | ((~k>>6)&15)<<3 | ((wl&1)<<2));
                    v[4]=uint8_t(0xc0|((k>>3)&7)<<3|(k&7));v[5]=uint8_t(k);
                    if(!check(v,6))return 6;
                }
            }
        }
        cs_close(&normal);cs_close(&target);
    }
#ifdef _WIN32
    VirtualFree(area,0,MEM_RELEASE);
#else
    munmap(area,page*2);
#endif
    if (hits[0]!=0 || (hits[1]>0)!=candidate) return 7;
    std::printf("%llu %llu %llu\n",trials,hits[0],hits[1]);
    return 0;
}
