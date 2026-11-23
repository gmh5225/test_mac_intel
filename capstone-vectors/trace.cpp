#include <capstone/capstone.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>
extern "C" bool X86_disasmIterText(csh,const uint8_t **,size_t *,uint64_t *,cs_insn *);
extern "C" {
unsigned long long vector_writes[2][3][2], vector_calls;
}
static uint64_t fingerprint(uint64_t h,const void *data,size_t n) {
    const auto *p=static_cast<const uint8_t *>(data);
    while(n--) h=(h^*p++)*UINT64_C(1099511628211);
    return h;
}
int main(int argc,char **argv) {
    if(argc!=4)return 1;
    const cs_mode mode=argv[1][0]=='3'?CS_MODE_32:CS_MODE_64;
    std::ifstream file(argv[2],std::ios::binary);
    if(!file)return 2;
    const std::vector<uint8_t> text{std::istreambuf_iterator<char>(file),{}};
    csh handle;
    if(cs_open(CS_ARCH_X86,mode,&handle))return 3;
    for(int detail:{0,1})for(int specialized:{0,1}) {
        if(cs_option(handle,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF))return 4;
        const auto next=specialized?X86_disasmIterText:cs_disasm_iter;
        std::ifstream spans(argv[3]);if(!spans)return 5;
        size_t start,n,valid=0,invalid=0;
        uint64_t ip,digest=UINT64_C(14695981039346656037);
        std::memset(vector_writes,0,sizeof(vector_writes));
        vector_calls=0;
        unsigned long long written_records=0, written_failures=0, printed=0, vector_records=0;
        while(spans>>start>>n>>ip) {
            if(start>text.size()||n>text.size()-start)return 6;
            const uint8_t *p=text.data()+start;
            while(n) {
                cs_insn rec;cs_detail info;
                std::memset(&rec,0xa5,sizeof(rec));std::memset(&info,0x5a,sizeof(info));
                rec.illegal=rec.is_alias=rec.usesAliasDetails=false;rec.alias_id=0;
                rec.detail=detail?&info:nullptr;
                const uint8_t *cursor=p;auto len=n;auto addr=ip;
                auto before=vector_calls;
                bool ok=next(handle,&cursor,&len,&addr,&rec);
                if(rec.detail!=(detail?&info:nullptr))return 7;
                rec.detail=nullptr;
                digest=fingerprint(digest,&rec,sizeof(rec));
                if(detail)digest=fingerprint(digest,&info,offsetof(cs_detail,x86)+sizeof(cs_x86));
                if(ok) {
                    if(!rec.size||rec.size>n||cursor!=p+rec.size||len!=n-rec.size||addr!=ip+rec.size)return 8;
                    written_records+=vector_calls!=before;
                    const char *end=static_cast<const char *>(std::memchr(rec.op_str,0,sizeof(rec.op_str)));
                    if(!end)return 10;
                    unsigned names=0;
                    for(const char *q=rec.op_str;end-q>=4;++q)
                        if((*q=='x'||*q=='y'||*q=='z') && q[1]=='m' && q[2]=='m' &&
                           q[3]>='0' && q[3]<='9') ++names;
                    printed+=names; vector_records+=names!=0;
                    p=cursor;n=len;ip=addr;++valid;
                } else {
                    if(cursor!=p||len!=n||addr!=ip)return 9;
                    written_failures+=vector_calls-before; ++p;--n;++ip;++invalid;
                }
            }
        }
        std::printf("%d %d %zu %zu %llu %llu %llu %llu %llu",detail,specialized,valid,invalid,
            (unsigned long long)digest,printed,vector_records,written_records,written_failures);
        unsigned long long total=0;
        for(const auto &kind:vector_writes)for(const auto &bank:kind)for(const auto count:bank) {
            std::printf(" %llu",count);
            total+=count;
        }
        if(total!=vector_calls)return 11;
        std::puts("");
    }
    return cs_close(&handle)!=CS_ERR_OK;
}
