#include <capstone/capstone.h>
#include <dlfcn.h>
#include <array>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {
struct Api {
    explicit Api(const char* path) : library(dlopen(path, RTLD_NOW | RTLD_LOCAL)) {
        if (!library) std::abort();
    }
    void* library;
    template<class T> T resolve(const char* name) {
        auto* symbol = dlsym(library, name);
        if (!symbol) std::abort();
        return reinterpret_cast<T>(symbol);
    }
    decltype(&cs_option) option = resolve<decltype(option)>("cs_option");
    decltype(&cs_open) open = resolve<decltype(open)>("cs_open");
    decltype(&cs_close) close = resolve<decltype(close)>("cs_close");
    decltype(&cs_disasm_iter) iter = resolve<decltype(iter)>("cs_disasm_iter");
};
Api* active;
cs_detail* writing;
int calls;
bool restore;
cs_opt_mem defaults{std::malloc, std::calloc, std::realloc, std::free, std::vsnprintf};

int format(char* dst, size_t n, const char* fmt, va_list args) {
    ++calls;
    // A caller can reach its own cs_insn while its formatter runs.
    for (size_t i = 1; i < 8; ++i)
        std::memset(&writing->x86.operands[i], int(0x30 + i), sizeof(cs_x86_op));
    if (restore && active->option(0, CS_OPT_MEM, reinterpret_cast<size_t>(&defaults)))
        std::abort();
    return std::vsnprintf(dst, n, fmt, args);
}

struct Record { cs_insn insn; cs_detail detail; int calls; };
void read(Api& api, cs_mode mode, int kind, const std::vector<uint8_t>& data, Record& result) {
    active=&api;
    if(api.option(0, CS_OPT_MEM, reinterpret_cast<size_t>(&defaults))) std::abort();
    csh h;
    if(api.open(CS_ARCH_X86,mode,&h) || api.option(h,CS_OPT_DETAIL,CS_OPT_ON)) std::abort();
    cs_opt_mem hook=defaults; hook.vsnprintf=format;
    calls=0; restore=kind==2;
    std::memset(&result, 0xa5, sizeof(result));
    result.insn.detail=writing=&result.detail;
    if(kind && api.option(0, CS_OPT_MEM, reinterpret_cast<size_t>(&hook))) std::abort();
    auto* p=data.data(); size_t left=data.size(); uint64_t ip=0x12345678;
    if(!api.iter(h,&p,&left,&ip,&result.insn) || left || p!=data.data()+data.size() ||
       result.detail.x86.op_count!=2 || result.detail.x86.operands[0].type!=X86_OP_REG)
        std::abort();
    result.calls=calls;
    result.insn.detail=nullptr;
    if(api.option(0, CS_OPT_MEM, reinterpret_cast<size_t>(&defaults)) || api.close(&h)) std::abort();
}
}
int main(int argc,char** argv) {
    if(argc!=3) return 1;
    Api base(argv[1]), trial(argv[2]);
    unsigned cases=0, observed=0, restored=0;
    for(auto mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64})
        for(int hook:{0,1,2}) for(uint8_t opcode:{0x04,0x14,0x24,0x3c,0xa8}) {
            for(uint8_t imm:{0x0e,0x7f,0xd8}) {
                std::vector<uint8_t> data{opcode,imm};
                Record a{},b{}; read(base,mode,hook,data,a); read(trial,mode,hook,data,b);
                if(a.calls!=b.calls || std::memcmp(&a.insn,&b.insn,sizeof(a.insn)) ||
                   std::memcmp(&a.detail,&b.detail,sizeof(a.detail))) return 3;
                if(a.calls) {
                    const auto* moved=reinterpret_cast<unsigned char*>(&b.detail.x86.operands[7]);
                    for(size_t i=0;i<sizeof(cs_x86_op);++i) if(moved[i]!=0x36) return 4;
                    ++observed;
                    restored+=hook==2;
                }
                ++cases;
            }
        }
    std::printf("{\"cases\":%u,\"observed_tail_moves\":%u,\"self_restoring_hooks\":%u}\n",cases,observed,restored);
    return observed && restored ? 0 : 5;
}
