#include "cs_priv.h"
#include "Mapping.h"
#include "SStream.h"
#include <stdio.h>
#include <string.h>
#include "alias-names.inc"

static unsigned expected(const name_map *rows, size_t count, const char *str)
{
    while (*str == ' ' || *str == '\t') str++;
    size_t len=0;
    while (len<15 && str[len] && str[len]!=' ' && str[len]!='\t' && str[len]!='.') len++;
    for (size_t i=0;i<count;i++) {
        const char *name=rows[i].name;
        if (name && strlen(name)==len && memcmp(name,str,len)==0) return rows[i].id;
    }
    return 0;
}
typedef void (*Lookup)(MCInst *,const SStream *,const name_map *,int);
static int sweep(cs_arch arch, Lookup lookup, const name_map *rows, size_t count, unsigned long *total)
{
    MCInst mi={0};cs_struct handle={0};cs_insn insn={0};SStream stream={0};mi.csh=&handle;handle.arch=arch;mi.flat_insn=&insn;
    for (size_t i=0;i<count;i++) {
        const char *name=rows[i].name;if(!name)continue;size_t len=strlen(name);
        for (size_t end=0;end<=len;end++) for(unsigned value=0;value<256;value++) for(unsigned pad=0;pad<2;pad++) {
            size_t k=pad?2:0;char *buf=stream.buffer;memcpy(buf," \t",2);memcpy(buf+k,name,end);buf[k+end]=(char)value;
            memcpy(buf+k+end+1,"x.y, z",7);
            unsigned match=expected(rows,count,buf);
            for(unsigned active=0;active<2;active++){
                mi.isAliasInstr=active;insn.alias_id=0xffffffffu;
                lookup(&mi,&stream,rows,(int)count);
                if(insn.alias_id!=(active?match:0)){fprintf(stderr,"alias mismatch arch=%d name=%s end=%zu byte=%u pad=%u\n",arch,name,end,value,pad);return 1;}
                ++*total;
            }
        }
    }
    return 0;
}
int main(void)
{
    unsigned long total=0;
    if(sweep(CS_ARCH_AARCH64,map_set_aarch64_alias_id,arm_names,sizeof(arm_names)/sizeof(arm_names[0]),&total)||
       sweep(CS_ARCH_MIPS,map_set_mips_alias_id,mips_names,sizeof(mips_names)/sizeof(mips_names[0]),&total))return 1;
    printf("%lu\n",total);return total>500000?0:2;
}
