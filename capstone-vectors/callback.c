#include "cs_priv.h"
#include <stdio.h>
#include <string.h>

static Printer_t base_print;
static PostPrinter_t base_post;
static unsigned kind, calls;
static const char spelling[] = "a|b\tQ";
static void replace(SStream *s)
{
    memcpy(s->buffer, spelling, sizeof(spelling));
    s->index = sizeof(spelling) - 1;
    ++calls;
}
static void custom_print(MCInst *mi, SStream *s, void *info)
{
    base_print(mi, s, info);
    if (kind == 2)
        mi->csh->printer = base_print;
    replace(s);
}
static void custom_post(csh h, cs_insn *insn, SStream *s, MCInst *mi)
{
    if (base_post)
        base_post(h, insn, s, mi);
    replace(s);
}
int main(void)
{
    const cs_mode modes[] = {CS_MODE_16, CS_MODE_32, CS_MODE_64};
    const size_t syntax[] = {CS_OPT_SYNTAX_INTEL, CS_OPT_SYNTAX_ATT};
    const uint8_t code[][8] = {{0x89,0xc1}, {0x83,0xc0,1}, {0x0f,0xaf,0xd8}, {0xf3,0x0f,0x59,0xc8}};
    const size_t size[] = {2,3,3,4};
    unsigned count = 0;
    for (unsigned mode=0; mode<3; ++mode)
        for (unsigned syn=0; syn<2; ++syn)
            for (unsigned detail=0; detail<2; ++detail) {
                csh h;
                if (cs_open(CS_ARCH_X86,modes[mode],&h) ||
                    cs_option(h,CS_OPT_SYNTAX,syntax[syn]) ||
                    cs_option(h,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF))
                    return 1;
                cs_struct *handle=(cs_struct *)(uintptr_t)h;
                base_print=handle->printer;
                base_post=handle->post_printer;
                for (kind=0; kind<3; ++kind)
                    for (unsigned j=0;j<4;++j)
                        for (unsigned api=0;api<2;++api) {
                            handle->printer=kind==1?base_print:custom_print;
                            handle->post_printer=kind==1?custom_post:base_post;
                            calls=0;
                            cs_insn *out=NULL;
                            if (api==0) {
                                const uint8_t *p=code[j];size_t n=size[j];uint64_t addr=0x1000;
                                out=cs_malloc(h);
                                if (!out || !cs_disasm_iter(h,&p,&n,&addr,out) || n) return 2;
                            } else if (cs_disasm(h,code[j],size[j],0x1000,1,&out)!=1) return 3;
                            if (calls!=1 || strcmp(out->mnemonic,"a b") || strcmp(out->op_str,"Q")) {
                                fprintf(stderr,"mode=%u syntax=%u detail=%u callback=%u input=%u api=%u count=%u %s / %s\n",mode,syn,detail,kind,j,api,calls,out->mnemonic,out->op_str);
                                return 4;
                            }
                            cs_free(out,1);
                            ++count;
                        }
                handle->printer=base_print;handle->post_printer=base_post;
                cs_close(&h);
            }
    printf("%u\n",count);
    return 0;
}
