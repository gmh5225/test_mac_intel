#include <capstone/capstone.h>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>
static uint64_t digest(uint64_t h, const void *value, size_t size) {
    const auto *bytes=static_cast<const unsigned char *>(value);
    for (size_t i=0;i<size;++i) h=(h^bytes[i])*1099511628211ULL;
    return h;
}
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    std::ifstream source(argv[1],std::ios::binary);
    std::vector<uint8_t> data{std::istreambuf_iterator<char>(source),{}};
    if(data.size()<256 || data.size()%4)return 3;
    for(unsigned bits:{16U,32U}) for(bool big:{false,true})
    for(unsigned opts=0;opts<(cs_support(CS_SUPPORT_DIET)?2U:4U);++opts){
        csh h=0;
        if(cs_open(CS_ARCH_ARM,cs_mode((bits==16?CS_MODE_THUMB:CS_MODE_ARM)|(big?unsigned(CS_MODE_BIG_ENDIAN):0U)),&h))return 4;
        if(cs_option(h,CS_OPT_TEXT,opts?CS_OPT_ON:CS_OPT_OFF) ||
           cs_option(h,CS_OPT_DETAIL,opts<2?CS_OPT_OFF:(opts==2?unsigned(CS_OPT_ON):unsigned(CS_OPT_ON)|unsigned(CS_OPT_DETAIL_REAL))))return 5;
        uint64_t hash=14695981039346656037ULL;unsigned valid=0;
        for(size_t n=0;n<data.size();n+=4){
            uint8_t bytes[4];for(unsigned i=0;i<4;++i)bytes[big?3-i:i]=data[n+i];
            const uint8_t *p=bytes;size_t left=4;uint64_t ip=0x100000+n;
            cs_insn ins;cs_detail detail;std::memset(&ins,0x5a,sizeof(ins));std::memset(&detail,0xa5,sizeof(detail));
            ins.illegal=ins.is_alias=ins.usesAliasDetails=false;ins.detail=opts<2?nullptr:&detail;
            bool ok=cs_disasm_iter(h,&p,&left,&ip,&ins);
            if(ins.detail!=(opts<2?nullptr:&detail) || p-bytes!=ptrdiff_t(4-left) || ip!=0x100000+n+4-left)return 6;
            const unsigned status=cs_errno(h);ins.detail=nullptr;
            hash=digest(hash,&ins,sizeof(ins));hash=digest(hash,&detail,sizeof(detail));
            hash=digest(hash,&status,sizeof(status));hash=digest(hash,&left,sizeof(left));valid+=ok;
        }
        if(!valid)return 7;
        std::printf("%u %u %u %u %" PRIu64 "\n",bits,unsigned(big),opts,valid,hash);cs_close(&h);
    }
}
