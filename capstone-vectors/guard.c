#include "raw.h"
#include <dlfcn.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

typedef void (*reader)(const uint8_t *, size_t, cs_mode, ReaderState *);
typedef struct Encoding { unsigned size; uint8_t bytes[4]; } Encoding;
static const Encoding encodings[] = {
    {2,{0x0f,0xa4}}, {2,{0x0f,0xac}}, {1,{0x69}}, {1,{0x6b}},
    {4,{0xc4,0xe3,0x7b,0xf0}}, {4,{0xc4,0xe3,0xfb,0xf0}},
    {4,{0x8f,0xea,0x78,0x10}}, {4,{0x8f,0xea,0xf8,0x10}},
    {4,{0xc4,0xe3,0x73,0xf0}}, {4,{0x8f,0xea,0x70,0x10}},
};
static const Encoding prefixes[] = {
    {0,{0}}, {1,{0x66}}, {1,{0x67}}, {2,{0x66,0x67}}, {1,{0x48}},
    {2,{0x66,0x4f}}, {2,{0x67,0x4d}}, {1,{0xf0}}, {2,{0x2e,0x67}}
};
static const uint8_t sibs[] = {0x00,0x25,0x65,0x85,0xfc,0xff};
static const cs_mode modes[] = {CS_MODE_16,CS_MODE_32,CS_MODE_64};

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    reader decode[2];
    for (unsigned i=0;i<2;i++) {
        void *lib=dlopen(argv[i+1],RTLD_NOW|RTLD_LOCAL);
        if (!lib || !(decode[i]=(reader)dlsym(lib,"measure_raw_operands"))) {
            fprintf(stderr,"raw reader: %s\n",dlerror()); return 3;
        }
    }
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    uint8_t *pages=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_PRIVATE,-1,0);
    if (pages==MAP_FAILED || mprotect(pages+page,page,PROT_NONE)) return 4;
    uint64_t calls=0,invalid=0,rows[1024]={0};
    for (unsigned m=0;m<3;m++)
    for (unsigned p=0;p<sizeof(prefixes)/sizeof(prefixes[0]);p++)
    for (unsigned f=0;f<sizeof(encodings)/sizeof(encodings[0]);f++)
    for (unsigned mr=0;mr<256;mr++) {
        for (unsigned s=0;s<(((mr&7)==4 && mr<0xc0) ? sizeof(sibs) : 1);s++) {
            uint8_t bytes[24];
            unsigned pos=prefixes[p].size;
            memcpy(bytes,prefixes[p].bytes,pos);
            memcpy(bytes+pos,encodings[f].bytes,encodings[f].size);
            pos+=encodings[f].size;
            bytes[pos++]=(uint8_t)mr;
            bytes[pos++]=sibs[s];
            while (pos<sizeof(bytes)) { bytes[pos]=(uint8_t)(pos*97+mr*11+f); pos++; }
            for (unsigned n=0;n<=16;n++) {
                uint8_t *in=pages+page-n;
                memcpy(in,bytes,n);
                ReaderState a,b;
                decode[0](in,n,modes[m],&a);
                decode[1](in,n,modes[m],&b);
                if (memcmp(&a,&b,sizeof(a))) {
                    fprintf(stderr,"m=%u p=%u f=%u modrm=%02x sib=%02x n=%u status=%d/%d set=%d/%d\n",
                            m,p,f,mr,sibs[s],n,a.status,b.status,a.set,b.set); return 1;
                }
                ++calls;
                if (a.status) ++invalid;
                else if (a.set>=0 && a.set<1024) ++rows[a.set];
            }
        }
    }
    if (munmap(pages,2*page)) return 5;
    printf("%" PRIu64 " %" PRIu64 "\n",calls,invalid);
    for (unsigned i=0;i<1024;i++) if (rows[i]) printf("%u %" PRIu64 "\n",i,rows[i]);
    return 0;
}
