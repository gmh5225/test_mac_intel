#include <capstone/capstone.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <vector>

template<class T> T symbol(void *lib, const char *name) {
    void *p=dlsym(lib,name);
    if (!p) throw std::runtime_error(name);
    return reinterpret_cast<T>(p);
}

struct Reader {
    void *lib;
    decltype(&cs_open) open;
    decltype(&cs_option) option;
    decltype(&cs_disasm_iter) step;
    decltype(&cs_malloc) alloc;
    decltype(&cs_free) release;
    decltype(&cs_close) close;
    std::array<csh,2> handle{};
    std::array<cs_insn*,2> record{};
    explicit Reader(const char *file) : lib(dlopen(file,RTLD_LOCAL|RTLD_NOW)),
      open(symbol<decltype(open)>(lib,"cs_open")), option(symbol<decltype(option)>(lib,"cs_option")),
      step(symbol<decltype(step)>(lib,"cs_disasm_iter")), alloc(symbol<decltype(alloc)>(lib,"cs_malloc")),
      release(symbol<decltype(release)>(lib,"cs_free")),close(symbol<decltype(close)>(lib,"cs_close")) {
        if (!lib) throw std::runtime_error(file);
        for (unsigned d=0; d<2; ++d) {
            if (open(CS_ARCH_WASM,cs_mode(0),&handle[d]) || option(handle[d],CS_OPT_DETAIL,d?CS_OPT_ON:CS_OPT_OFF)) std::abort();
            record[d]=alloc(handle[d]);if (!record[d]) std::abort();
        }
    }
    ~Reader() {
        for (unsigned d=0; d<2; ++d) {release(record[d],1);close(&handle[d]);}
        dlclose(lib);
    }
};
struct Outcome {bool accepted;size_t offset,left;uint64_t ip;cs_insn flat;cs_detail details;};
static void evaluate(Reader&reader,unsigned d,const uint8_t *p,size_t n,Outcome&out) {
    cs_insn *insn=reader.record[d];cs_detail *detail=insn->detail;
    std::memset(insn,0xa5,sizeof(*insn));insn->detail=detail;
    if(detail) std::memset(detail,0x5a,sizeof(*detail));
    const auto *cursor=p;size_t left=n;uint64_t ip=0x1000;
    out.accepted=reader.step(reader.handle[d],&cursor,&left,&ip,insn);
    if(insn->detail!=detail) std::abort();
    out.offset=size_t(cursor-p);out.left=left;out.ip=ip;
    std::memcpy(&out.flat,insn,sizeof(*insn));out.flat.detail=nullptr;
    if(detail) std::memcpy(&out.details,detail,sizeof(*detail));
}
int main(int argc,char **argv) {
    if(argc!=3)return 2;
    Reader first(argv[1]),second(argv[2]);
    if(first.step==second.step) return 5;
    const size_t page=static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto *mem=static_cast<uint8_t*>(mmap(nullptr,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0));
    if(mem==MAP_FAILED || mprotect(mem+page,page,PROT_NONE))return 3;
    size_t cases=0,valid=0,invalid=0;
    auto check=[&](const std::vector<uint8_t>&bytes,bool well_formed){
        for(size_t n=0;n<=bytes.size();++n){
            uint8_t *p=mem+page-n;
            if(n)std::memcpy(p,bytes.data(),n);
            for(unsigned d=0;d<2;++d){
                Outcome a{},b{};evaluate(first,d,p,n,a);evaluate(second,d,p,n,b);
                if(a.accepted!=b.accepted || a.offset!=b.offset || a.left!=b.left || a.ip!=b.ip ||
                   std::memcmp(&a.flat,&b.flat,sizeof(a.flat)) || (d && std::memcmp(&a.details,&b.details,sizeof(a.details))) ||
                   a.accepted!=(well_formed && n==bytes.size())) {
                    std::fprintf(stderr,"count=%u length=%zu/%zu detail=%u expected=%u observed=%u/%u\n",bytes[1],n,bytes.size(),d,well_formed&&n==bytes.size(),a.accepted,b.accepted);
                    std::exit(4);
                }
                ++cases;if(a.accepted)++valid;else ++invalid;
            }
        }
    };
    for(unsigned count : {0u,1u,7u,8u,9u,15u,16u,17u,24u,32u}){
        for(unsigned mask=0;mask<256;++mask){
            std::vector<uint8_t> bytes{0x0e,static_cast<uint8_t>(count)};
            for(unsigned j=0;j<count;++j){
                if(mask&(1u<<(j&7))) {bytes.push_back(0x81);bytes.push_back(1);}
                else bytes.push_back(static_cast<uint8_t>((j*13)&127));
            }
            bytes.push_back(3);check(bytes,true);
        }
        for(unsigned pos=0;pos<=count;++pos){
            for(unsigned last : {0u,15u,16u,127u,128u,255u}){
                std::vector<uint8_t> bytes{0x0e,static_cast<uint8_t>(count)};
                for(unsigned j=0;j<=count;++j){
                    if(j==pos) {bytes.insert(bytes.end(),4,0x80);bytes.push_back(static_cast<uint8_t>(last));}
                    else bytes.push_back(0);
                }
                check(bytes,last<=15);
            }
        }
    }
    munmap(mem,2*page);
    std::printf("%zu %zu %zu\n",cases,valid,invalid);
}
