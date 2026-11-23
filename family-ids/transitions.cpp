#define main baseline_record_corpus_main
#include "public-records.cpp"
#undef main
#include <array>
int main(int argc,char **argv)
{
    if(argc!=3)return 1;
    Api old(argv[1],CS_MODE_32),updated(argv[2],CS_MODE_32);
    unsigned count=0;
    std::array<std::array<uint8_t,8>,8> codes{{
        {0x48,0x8b,0xc1}, {0x67,0x8b,0x04,0x24}, {0xc5,0xf8,0x77},
        {0x66,0x48,0xd9,0x30}, {0x0f,0x0b}, {0x62,0xf1,0x7d,0x48,0xfe,0xd9},
        {0xc5,0xdc,0x59,0xc4}, {0xc4,0,0,0xff}
    }};
    const size_t modes[]={CS_MODE_16,CS_MODE_32,CS_MODE_64,CS_MODE_64|CS_MODE_X86_INTEL,
                           CS_MODE_32|CS_MODE_X86_AMD,CS_MODE_X86_INTEL|CS_MODE_X86_AMD};
    const size_t details[]={CS_OPT_ON,CS_OPT_DETAIL_REAL,CS_OPT_OFF,CS_OPT_DETAIL_REAL|CS_OPT_ON,CS_OPT_OFF};
    auto set=[&](cs_opt_type opt,size_t val){return old.option(old.handle,opt,val)==updated.option(updated.handle,opt,val);};
    for(unsigned pass=0;pass<2;++pass)for(auto mode:modes) {
        if(!set(CS_OPT_MODE,mode))return 2;
        for(auto dt:details)for(auto text:{CS_OPT_ON,CS_OPT_OFF})
            for(auto skip:{CS_OPT_OFF,CS_OPT_ON}) {
                if (!set(CS_OPT_TEXT,text) || !set(CS_OPT_DETAIL,dt) || !set(CS_OPT_SKIPDATA,skip))return 3;
                for(auto &bytes:codes)for(unsigned n=0;n<=bytes.size();++n)
                    for(bool retained:{false,true}) {
                        cs_detail da,db;cs_insn a,b;
                        memset(&da,0xa5,sizeof(da));memcpy(&db,&da,sizeof(db));memset(&a,0x5a,sizeof(a));
                        a.illegal=a.is_alias=a.usesAliasDetails=false;a.alias_id=0;memcpy(&b,&a,sizeof(b));
                        a.detail=retained?&da:nullptr;b.detail=retained?&db:nullptr;
                        const uint8_t *pa=bytes.data(),*pb=pa;
                        size_t na=n,nb=n;uint64_t ia=UINT64_MAX-3,ib=ia;
                        bool va=old.iter(old.handle,&pa,&na,&ia,&a),vb=updated.iter(updated.handle,&pb,&nb,&ib,&b);
                        if(a.detail!=(retained?&da:nullptr) || b.detail!=(retained?&db:nullptr))return 5;
                        a.detail=b.detail=nullptr;
                        if(va!=vb || pa!=pb || ia!=ib || na!=nb || old.error(old.handle)!=updated.error(updated.handle) ||
                            memcmp(&a,&b,sizeof(a)) || memcmp(&da,&db,sizeof(da))) {
                            fprintf(stderr,"mode %zu detail %zu text %d skip %d retained %d n %u\n",mode,dt,text,skip,retained,n);
                            return 6;
                        }
                        ++count;
                    }
            }
    }
    printf("%u\n",count);
}
