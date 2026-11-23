#include <capstone/capstone.h>
#include <dlfcn.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>

struct Library {
    void *image;
    decltype(&cs_open) open;
    decltype(&cs_disasm_iter) iter;
    decltype(&cs_option) option;
    decltype(&cs_close) close;
    explicit Library(const char *p): image(dlopen(p,RTLD_NOW|RTLD_LOCAL)),
        open(reinterpret_cast<decltype(open)>(dlsym(image,"cs_open"))),
        iter(reinterpret_cast<decltype(iter)>(dlsym(image,"cs_disasm_iter"))),
        option(reinterpret_cast<decltype(option)>(dlsym(image,"cs_option"))),
        close(reinterpret_cast<decltype(close)>(dlsym(image,"cs_close"))) {}
};
int main(int argc,char **argv) {
    if(argc!=3)return 1;
    Library ref(argv[1]),test(argv[2]);
    if(!ref.image||!test.image)return 2;
    unsigned count=0;
    for(bool big:{false,true})for(bool wide:{false,true}) {
        cs_mode mode=cs_mode((wide?CS_MODE_MIPS64:CS_MODE_MIPS32)|(big?CS_MODE_BIG_ENDIAN:0));
        csh a=0,b=0;
        if(ref.open(CS_ARCH_MIPS,mode,&a) || test.open(CS_ARCH_MIPS,mode,&b) ||
           ref.option(a,CS_OPT_TEXT,CS_OPT_OFF) || test.option(b,CS_OPT_TEXT,CS_OPT_OFF))return 3;
        for(unsigned major:{4,5,10,11,32,33,36,37,40,41})
            for(unsigned rs=0;rs<32;rs++)for(unsigned rt=0;rt<32;rt++)
                for(unsigned low:{0,1,9,0x7fff,0x8000,0xabcd,0xfffe,0xffff}) {
                    uint32_t word=(major<<26)|(rs<<21)|(rt<<16)|low;
                    uint8_t bytes[4];for(unsigned i=0;i!=4;++i)bytes[big?3-i:i]=uint8_t(word>>(i*8));
                    const uint8_t *x=bytes,*y=bytes;size_t l=4,m=4;uint64_t u=UINT64_MAX-2,v=u;
                    cs_insn r,s;cs_detail dr,ds;memset(&r,count&1?0xa5:0x5a,sizeof(r));memset(&dr,0xc3,sizeof(dr));
                    r.is_alias=r.usesAliasDetails=r.illegal=(count&1)!=0;
                    memcpy(&s,&r,sizeof(s));memcpy(&ds,&dr,sizeof(ds));r.detail=&dr;s.detail=&ds;
                    bool aok=ref.iter(a,&x,&l,&u,&r),bok=test.iter(b,&y,&m,&v,&s);
                    if(r.detail!=&dr||s.detail!=&ds)return 4;
                    r.detail=s.detail=nullptr;
                    if(!aok||!bok||l!=m||u!=v||x!=y||memcmp(&r,&s,sizeof(r))||memcmp(&dr,&ds,sizeof(dr))) {
                        fprintf(stderr,"mode %u major %u word %08x ids %u %u\n",unsigned(mode),major,word,r.id,s.id);
                        return 5;
                    }
                    ++count;
                }
        ref.close(&a);test.close(&b);
    }
    printf("%u complete MIPS branch, comparison and load/store records\n",count);
}
