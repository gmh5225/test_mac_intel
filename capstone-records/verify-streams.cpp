#include <capstone/capstone.h>
#include "SStream.h"
#include <dlfcn.h>
#include <cstdio>
#include <cstring>
#include <stdexcept>

using Print = void (*)(csh, unsigned, SStream *);
int main(int argc, char **argv)
{
 if(argc!=3)return 1;
 void *a=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL),*b=dlopen(argv[2],RTLD_NOW|RTLD_LOCAL);
 if(!a||!b)throw std::runtime_error(dlerror());
 auto open_a=(decltype(&cs_open))dlsym(a,"cs_open"),open_b=(decltype(&cs_open))dlsym(b,"cs_open");
 auto option_a=(decltype(&cs_option))dlsym(a,"cs_option"),option_b=(decltype(&cs_option))dlsym(b,"cs_option");
 auto close_a=(decltype(&cs_close))dlsym(a,"cs_close"),close_b=(decltype(&cs_close))dlsym(b,"cs_close");
 auto print_a=(Print)dlsym(a,"cs_test_mips_print_register"),print_b=(Print)dlsym(b,"cs_test_mips_print_register");
 if(!open_a||!open_b||!option_a||!option_b||!close_a||!close_b||!print_a||!print_b||print_a==print_b)return 2;
 csh ha=0,hb=0;
 if(open_a(CS_ARCH_MIPS,CS_MODE_MIPS32R2,&ha)||open_b(CS_ARCH_MIPS,CS_MODE_MIPS32R2,&hb))return 3;
 size_t count=0;
 const unsigned syntaxes[]={0,CS_OPT_SYNTAX_NOREGNAME,CS_OPT_SYNTAX_NO_DOLLAR,CS_OPT_SYNTAX_NOREGNAME|CS_OPT_SYNTAX_NO_DOLLAR};
 for(auto syntax:syntaxes) {
  if(option_a(ha,CS_OPT_SYNTAX,syntax)||option_b(hb,CS_OPT_SYNTAX,syntax))return 4;
  for(unsigned reg=1;reg<MIPS_REG_ENDING;++reg)for(unsigned flags=0;flags<16;++flags)
  for(unsigned index=0;index<516;++index) {
   SStream x,y;std::memset(&x,0xa5,sizeof(x));x.index=index<515?index:SIZE_MAX;
   x.is_closed=flags&1;x.markup_stream=flags&2;x.prefixed_by_markup=flags&4;x.unsigned_num=flags&8;
   if(x.index<SSTREAM_BUF_LEN)x.buffer[x.index]=0;
   std::memcpy(&y,&x,sizeof(x));print_a(ha,reg,&x);print_b(hb,reg,&y);
   if(std::memcmp(&x,&y,sizeof(x))) {
    std::fprintf(stderr,"MIPS stream differs: syntax=%u reg=%u flags=%u index=%u\n",syntax,reg,flags,index);return 5;
   }
   ++count;
  }
 }
 close_a(&ha);close_b(&hb);
 std::printf("matched %zu complete MIPS stream records\n",count);
}
