#include <capstone/capstone.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    cs_err (*open)(cs_arch, cs_mode, csh *);
    cs_err (*option)(csh, cs_opt_type, size_t);
    bool (*iter)(csh, const uint8_t **, size_t *, uint64_t *, cs_insn *);
    cs_err (*close)(csh *);
    csh handle;
} Decoder;

static int compare(Decoder *old, Decoder *candidate, const uint8_t *bytes, size_t n,
                   bool details)
{
    cs_insn insn[2];
    cs_detail detail[2];
    Decoder *both[] = {old, candidate};
    bool valid[2];
    size_t rest[2] = {n, n};
    uint64_t address[] = {0x12345678, 0x12345678};
    memset(insn, 0xa7, sizeof(insn));
    memset(detail, 0x6d, sizeof(detail));
    for (unsigned i = 0; i < 2; ++i) {
        const uint8_t *pos = bytes;
        insn[i].detail = details ? &detail[i] : NULL;
        valid[i] = both[i]->iter(both[i]->handle,&pos,&rest[i],&address[i],&insn[i]);
        if (pos != bytes + (n - rest[i])) return 1;
        insn[i].detail = NULL;
    }
    if (valid[0]!=valid[1] || rest[0]!=rest[1] || address[0]!=address[1] ||
        memcmp(&insn[0], &insn[1], sizeof(cs_insn)) ||
        memcmp(&detail[0], &detail[1], sizeof(cs_detail))) {
        fprintf(stderr,"postprinter mismatch bytes=");
        for(size_t i=0;i<n;i++) fprintf(stderr,"%02x",bytes[i]);
        fprintf(stderr," old=%.32s %.160s new=%.32s %.160s\n",insn[0].mnemonic,insn[0].op_str,insn[1].mnemonic,insn[1].op_str);
        return 1;
    }
    return 0;
}

static int decorated(char *s, size_t n, const char *fmt, va_list ap)
{
    (void)fmt; (void)ap;
    return snprintf(s,n,"{1to8}");
}

int main(int argc,char **argv)
{
    if(argc!=2) return 2;
    void *lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
    if(!lib) return 2;
    Decoder d[]={{dlsym(lib,"cs_open"),dlsym(lib,"cs_option"),dlsym(lib,"cs_disasm_iter"),dlsym(lib,"cs_close"),0},
                 {cs_open,cs_option,cs_disasm_iter,cs_close,0}};
    const cs_mode modes[]={CS_MODE_16,CS_MODE_32,CS_MODE_64};
    const uint8_t prefixes[][3]={{0},{0x66},{0x67},{0x48},{0x66,0x48},{0xf3},{0x0f},{0xc5,0xf8},{0x62,0xf1,0x7c}};
    const uint8_t counts[]={0,1,1,1,2,1,1,2,3};
    unsigned long compared=0;
    for(unsigned custom=0;custom<2;custom++) {
        cs_opt_mem hooks={malloc,calloc,realloc,free,decorated};
        if(custom)
            for (unsigned i=0;i<2;i++)
                if(d[i].option(0,CS_OPT_MEM,(size_t)&hooks)!=CS_ERR_OK) return 3;
        for(unsigned m=0;m<3;m++) {
            for(unsigned i=0;i<2;i++)
                if(d[i].open(CS_ARCH_X86,modes[m],&d[i].handle)!=CS_ERR_OK) return 3;
            for(unsigned details=0;details<2;details++) {
                for(unsigned i=0;i<2;i++)
                    if(d[i].option(d[i].handle,CS_OPT_DETAIL,details?CS_OPT_ON:CS_OPT_OFF)!=CS_ERR_OK) return 3;
                for(unsigned p=0;p<sizeof(counts);p++) {
                    for(unsigned op=0;op<256;op++)
                        for(unsigned modrm=0;modrm<256;modrm+=custom?17:1) {
                            uint8_t code[15]={0};
                            memcpy(code,prefixes[p],counts[p]); code[counts[p]]=op; code[counts[p]+1]=modrm;
                            for(unsigned j=counts[p]+2;j<sizeof(code);j++) code[j]=(uint8_t)(j*37+modrm);
                            if(compare(&d[0],&d[1],code,sizeof(code),details)) return 4;
                            compared++;
                        }
                }
            }
            for(unsigned i=0;i<2;i++)
                if(d[i].close(&d[i].handle)!=CS_ERR_OK) return 3;
        }
    }
    printf("Matched %lu complete iterator, instruction and detail states with default and decorating formatters\n",compared);
    dlclose(lib);
    return 0;
}
