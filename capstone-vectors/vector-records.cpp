#include <capstone/capstone.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

extern "C" bool X86_disasmIter32(csh,const uint8_t **,size_t *,uint64_t *,cs_insn *);
extern "C" bool X86_disasmIterText(csh,const uint8_t **,size_t *,uint64_t *,cs_insn *);
using Reader = decltype(&X86_disasmIter32);

static void mix(uint64_t &hash, const void *ptr, size_t size)
{
    const auto *bytes = static_cast<const unsigned char *>(ptr);
    for (size_t i=0; i<size; ++i)
        hash=(hash ^ bytes[i])*UINT64_C(1099511628211);
}

int main()
{
    const std::array<std::array<uint8_t, 8>, 12> corpus{{
        {0x48,0x8b,0xc1}, {0x67,0x8b,0x04,0x24}, {0xc5,0xf8,0x77},
        {0x66,0x48,0xd9,0x30}, {0x0f,0x0b}, {0x62,0xf1,0x7d,0x48,0xfe,0xd9},
        {0xc5,0xdc,0x59,0xc4}, {0xc4,0,0,0xff}, {0x0f,0xa4,0xcb,0x80},
        {0x8b,0x95,0x21,0xfe,0xff,0xff}, {0xeb,0x80}, {0x83,0xd8,0xff}
    }};
    const size_t modes[] = {CS_MODE_16, CS_MODE_32, CS_MODE_64, CS_MODE_64|CS_MODE_X86_INTEL,
                            CS_MODE_32|CS_MODE_X86_AMD, CS_MODE_X86_INTEL|CS_MODE_X86_AMD};
    const Reader readers[] = {cs_disasm_iter, X86_disasmIter32, X86_disasmIterText};
    const size_t page=size_t(sysconf(_SC_PAGESIZE));
    auto *arena=static_cast<uint8_t *>(mmap(nullptr,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0));
    if(arena==MAP_FAILED || mprotect(arena+page,page,PROT_NONE)) return 1;
    const unsigned options[]={CS_OPT_OFF,CS_OPT_ON,CS_OPT_DETAIL_REAL|CS_OPT_ON};
    for (Reader read: readers) {
        csh handle=0;
        if(cs_open(CS_ARCH_X86,CS_MODE_32,&handle)!=CS_ERR_OK ||
           cs_option(handle,CS_OPT_DETAIL,CS_OPT_ON)!=CS_ERR_OK) return 2;
        cs_insn *retained=cs_malloc(handle);
        if(!retained || !retained->detail) return 3;
        uint64_t hash=UINT64_C(14695981039346656037);
        unsigned checks=0;
        for (size_t mode:modes) for(unsigned profile=0;profile<6;++profile) {
            auto apply=[&](cs_opt_type option,size_t value) {
                const auto err=cs_option(handle,option,value);
                mix(hash,&err,sizeof(err));
            };
            apply(CS_OPT_MODE,mode);
            apply(CS_OPT_TEXT,profile==2?CS_OPT_OFF:CS_OPT_ON);
            apply(CS_OPT_SYNTAX,profile==3?CS_OPT_SYNTAX_ATT:CS_OPT_SYNTAX_INTEL);
            apply(CS_OPT_UNSIGNED,profile==4?CS_OPT_ON:CS_OPT_OFF);
            cs_opt_mnem mnem{X86_INS_MOV,profile==5?"move":nullptr};
            apply(CS_OPT_MNEMONIC,reinterpret_cast<uintptr_t>(&mnem));
            for (unsigned flags:options) for(unsigned skip:{CS_OPT_ON,CS_OPT_OFF}) {
                apply(CS_OPT_DETAIL,flags);
                apply(CS_OPT_SKIPDATA,skip);
                cs_insn *fresh=cs_malloc(handle);
                if(!fresh) return 4;
                for(auto *record:{retained,fresh}) for(const auto &bytes:corpus) for(size_t n=0;n<=bytes.size();++n) {
                    auto *start=arena+page-n;
                    std::memcpy(start,bytes.data(),n);
                    const uint8_t *ptr=start;
                    uint64_t ip=UINT64_MAX-3;
                    size_t left=n;
                    cs_detail *detail=record->detail;
                    std::memset(record,0,sizeof(*record));
                    std::memset(record->bytes,0x9b,sizeof(record->bytes));
                    std::memset(record->mnemonic,0x9b,sizeof(record->mnemonic));
                    std::memset(record->op_str,0x9b,sizeof(record->op_str));
                    if(detail) std::memset(detail,0x37,sizeof(*detail));
                    record->detail=detail;
                    const bool ok=read(handle,&ptr,&left,&ip,record);
                    const auto err=cs_errno(handle);
                    const size_t distance=size_t(ptr-start);
                    if(record->detail!=detail || distance>n || left!=n-distance) return 5;
                    record->detail=nullptr;
                    mix(hash,record,sizeof(*record));
                    if(detail) mix(hash,detail,sizeof(*detail));
                    record->detail=detail;
                    mix(hash,&ok,sizeof(ok)); mix(hash,&err,sizeof(err));
                    mix(hash,&ip,sizeof(ip)); mix(hash,&left,sizeof(left));
                    ++checks;
                }
                cs_free(fresh,1);
            }
        }
        std::printf("%u %llu\n",checks,static_cast<unsigned long long>(hash));
        cs_free(retained,1); cs_close(&handle);
    }
    return munmap(arena,2*page);
}
