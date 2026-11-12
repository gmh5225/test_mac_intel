#include <capstone/capstone.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>
#include <memory>
#include <vector>

// A bounded research consumer. Each invocation fixes the mode and uses a
// stock Intel formatter. Admit only known legacy position-independent forms.
static bool reusable(const cs_insn &insn, bool x64) {
    const uint8_t *bytes=insn.bytes;
    unsigned i=x64 && (bytes[0]&0xf0)==0x40 ? 1 : 0;
    if(i>=insn.size) return false;
    unsigned op=bytes[i++];
    if((op>=0x50 && op<=0x5f) || (!x64 && op>=0x40 && op<=0x4f) ||
       (op>=0x90 && op<=0x99) || (op>=0xb0 && op<=0xbf) ||
       op==0x68 || op==0x6a || op==0xc3 || op==0xcc) return true;
    if(op<0x40 && (op&7)>=4 && (op&7)<=5) return true; // AL/AX/EAX/RAX, immediate
    bool modrm=(op<0x40 && (op&7)<=3) || op==0x69 || op==0x6b ||
               op==0x80 || op==0x81 || op==0x83 || (op>=0x84 && op<=0x8e) ||
               op==0xc0 || op==0xc1 || op==0xc6 || op==0xc7 ||
               (op>=0xd0 && op<=0xd3) || op==0xf6 || op==0xf7 || op==0xfe;
    if(!modrm || i>=insn.size) return false;
    if(op==0xc7 && bytes[i]==0xf8) return false; // XBEGIN uses a relative target
    return !x64 || (bytes[i]&0xc7)!=0x05; // exclude RIP-relative addressing
}
static constexpr size_t used_detail=offsetof(cs_detail,x86)+sizeof(cs_x86);
struct Entry {
    unsigned id=0; uint8_t size=0;
    std::array<uint8_t,15> bytes{};
    char mnemonic[CS_MNEMONIC_SIZE], operands[160];
};
struct Cache {
    std::array<Entry,64> entries{};
    std::unique_ptr<unsigned char[]> details;
    bool x64; size_t hits=0;
    Cache(bool bits,bool full):details(full?new unsigned char[64*used_detail]:nullptr),x64(bits){}
    bool decode(csh h,const uint8_t **code,size_t *left,uint64_t *pc,cs_insn *insn) {
        size_t slot=(((*code)[0]*131)^(*left>1?(*code)[1]:0)) & (entries.size()-1);
        Entry &e=entries[slot];
        if(e.size && e.size<=*left && !std::memcmp(*code,e.bytes.data(),e.size)) {
            insn->address=*pc;insn->id=e.id;insn->size=e.size;
            std::memcpy(insn->bytes,*code,e.size);
            std::memcpy(insn->mnemonic,e.mnemonic,sizeof(e.mnemonic));
            std::memcpy(insn->op_str,e.operands,sizeof(e.operands));
            if(details) std::memcpy(insn->detail,details.get()+used_detail*slot,used_detail);
            *left-=e.size;*pc+=e.size;*code+=e.size;++hits;return true;
        }
        if(!cs_disasm_iter(h,code,left,pc,insn)) return false;
        if(reusable(*insn,x64)) {
            e.size=static_cast<uint8_t>(insn->size);e.id=insn->id;
            std::memcpy(e.bytes.data(),insn->bytes,e.size);
            std::memcpy(e.mnemonic,insn->mnemonic,sizeof(e.mnemonic));
            std::memcpy(e.operands,insn->op_str,sizeof(e.operands));
            if(details) std::memcpy(details.get()+used_detail*slot,insn->detail,used_detail);
        }
        return true;
    }
};
struct API {
    csh h=0;cs_insn *i=nullptr;
    API(bool x64,bool detail) {
        if(cs_open(CS_ARCH_X86,x64?CS_MODE_64:CS_MODE_32,&h)!=CS_ERR_OK ||
           cs_option(h,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF)!=CS_ERR_OK || !(i=cs_malloc(h))) std::abort();
    }
    ~API(){cs_free(i,1);cs_close(&h);}
};
static uint64_t consume(API &api,bool full) {
    auto *i=api.i;uint64_t v=i->id+std::strlen(i->mnemonic)+std::strlen(i->op_str);
    if(full) {
        cs_regs reads,writes;uint8_t nr,nw;
        if(cs_regs_access(api.h,i,reads,&nr,writes,&nw)!=CS_ERR_OK) std::abort();
        for(unsigned j=0;j<nr;++j)v+=reads[j];for(unsigned j=0;j<nw;++j)v+=writes[j];
        v+=i->detail->x86.op_count;
    }
    return v;
}
int main(int argc,char **argv) {
    if(argc!=6)return 2;
    std::ifstream f(argv[1],std::ios::binary);std::vector<uint8_t> bytes{std::istreambuf_iterator<char>{f},{}};
    bool x64=std::atoi(argv[2])==64,full=std::atoi(argv[3])!=0;
    int method=std::atoi(argv[4]),reps=std::atoi(argv[5]);
    if(bytes.empty() || reps<=0 || method<0 || method>2)return 2;
    API test(x64,full),ref(x64,full);
    uint64_t accepted=0,rejected=0,checksum=0,bounds=0,hits=0;
    const auto start=std::clock();
    for(int n=0;n<reps;++n) {
        // Start cold on each traversal; charge the new cache and destruction.
        std::unique_ptr<Cache> cache;
        if(method)cache=std::make_unique<Cache>(x64,full);
        auto *code=static_cast<const uint8_t*>(bytes.data());size_t left=bytes.size();
        uint64_t pc=0x100000ull+uint64_t(n%17)*0x293500;
        while(left) {
            const uint8_t *next=code;size_t remain=left;uint64_t va=pc;
            if(method==2) {
                // Changing poison checks untouched bytes and padding at every call.
                unsigned char seed=static_cast<unsigned char>((left+pc)*131+17);
                for(auto *api:{&test,&ref}) {auto *d=api->i->detail;std::memset(api->i,seed,sizeof(cs_insn));api->i->detail=d;if(d)std::memset(d,seed,sizeof(*d));}
            }
            bool ok=method?cache->decode(test.h,&code,&left,&pc,test.i):cs_disasm_iter(test.h,&code,&left,&pc,test.i);
            if(method==2) {
                bool valid=cs_disasm_iter(ref.h,&next,&remain,&va,ref.i);
                auto *a=test.i->detail,*b=ref.i->detail;test.i->detail=ref.i->detail=nullptr;
                bool bad=ok!=valid||cs_errno(test.h)!=cs_errno(ref.h)||pc!=va||code!=next||left!=remain||std::memcmp(test.i,ref.i,sizeof(cs_insn))||(a&&std::memcmp(a,b,sizeof(*a)));
                test.i->detail=a;ref.i->detail=b;
                if(bad){std::fprintf(stderr,"mismatch pc=%llx left=%zu size=%d hits=%zu\n",(unsigned long long)va,remain,test.i->size,cache->hits);return 3;}
            }
            if(!ok){++code;--left;++pc;++rejected;continue;}
            ++accepted;checksum+=consume(test,full);bounds=(bounds^(left+test.i->size))*1099511628211ull;
        }
        if(cache)hits+=cache->hits;
    }
    std::printf("%lld %llu %llu %llu %llu %llu\n",(long long)(std::clock()-start),(unsigned long long)accepted,(unsigned long long)rejected,(unsigned long long)checksum,(unsigned long long)bounds,(unsigned long long)hits);
}
