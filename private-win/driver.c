#include <windows.h>
#include <capstone/capstone.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef cs_err (CAPSTONE_API *Open)(cs_arch, cs_mode, csh *);
typedef cs_err (CAPSTONE_API *Option)(csh, cs_opt_type, size_t);
typedef cs_insn *(CAPSTONE_API *Allocate)(csh);
typedef bool (CAPSTONE_API *Iterate)(csh, const uint8_t **, size_t *, uint64_t *, cs_insn *);
typedef void (CAPSTONE_API *Free)(cs_insn *, size_t);
typedef cs_err (CAPSTONE_API *Close)(csh *);
struct result { uint64_t boundaries, values; unsigned count, rejected; };
static struct result decode(Iterate iter, csh h, cs_insn *insn, const uint8_t *data, size_t length, uint64_t ip, unsigned mode)
{
    const uint8_t *p = data;
    size_t left = length;
    struct result result = { 5381 };
    while (left) {
        if (!iter(h, &p, &left, &ip, insn)) {
            ++p; --left; ++ip; ++result.rejected;
            result.boundaries = result.boundaries * 33 + 17;
            continue;
        }
        ++result.count;
        result.boundaries = result.boundaries * 33 + insn->size;
        result.values += insn->id;
        if (mode) result.values += strlen(insn->mnemonic) + strlen(insn->op_str);
        if (mode == 2) {
            const cs_x86 *x = &insn->detail->x86;
            result.values += x->eflags + insn->detail->groups_count;
            for (unsigned n = 0; n < x->op_count; ++n) {
                const cs_x86_op *op = &x->operands[n];
                result.values += op->type + op->size + op->access;
                if (op->type == X86_OP_REG) result.values += op->reg;
                if (op->type == X86_OP_IMM) result.values += (uint64_t)op->imm;
                if (op->type == X86_OP_MEM) result.values += op->mem.base + op->mem.index + (uint64_t)op->mem.disp;
            }
        }
    }
    return result;
}
static uint64_t cpu(void)
{
    FILETIME create,end,k,u;
    if (!GetThreadTimes(GetCurrentThread(),&create,&end,&k,&u)) exit(8);
    return (((uint64_t)k.dwHighDateTime << 32) | k.dwLowDateTime) + (((uint64_t)u.dwHighDateTime << 32) | u.dwLowDateTime);
}
int main(int argc,char **argv)
{
    if (argc != 6) return 2;
    FILE *file=fopen(argv[2],"rb");
    if (!file || fseek(file,0,SEEK_END)) return 3;
    long length=ftell(file); rewind(file);
    uint8_t *data=malloc((size_t)length);
    if (!data || length<=0 || fread(data,1,length,file)!=(size_t)length) return 4;
    fclose(file);
    HMODULE module=LoadLibraryA(argv[1]); if (!module) return 5;
    Open open=(Open)GetProcAddress(module,"cs_open");
    Option option=(Option)GetProcAddress(module,"cs_option");
    Allocate allocate=(Allocate)GetProcAddress(module,"cs_malloc");
    Iterate iter=(Iterate)GetProcAddress(module,"cs_disasm_iter");
    Free release=(Free)GetProcAddress(module,"cs_free");
    Close close=(Close)GetProcAddress(module,"cs_close");
    if (!open || !option || !allocate || !iter || !release || !close) return 5;
    unsigned bits=atoi(argv[3]),mode=atoi(argv[4]),reps=atoi(argv[5]);
    csh h=0; if (!reps || open(CS_ARCH_X86,bits==64?CS_MODE_64:CS_MODE_32,&h)) return 6;
    if (option(h,CS_OPT_TEXT,mode?CS_OPT_ON:CS_OPT_OFF) || option(h,CS_OPT_DETAIL,mode==2?CS_OPT_ON:CS_OPT_OFF)) return 6;
    cs_insn *insn=allocate(h); if (!insn) return 6;
    DWORD_PTR allowed,system; if (!GetProcessAffinityMask(GetCurrentProcess(),&allowed,&system) || !SetThreadAffinityMask(GetCurrentThread(),allowed & (0-allowed))) return 7;
    uint64_t address=bits==64?UINT64_C(0x140001000):UINT64_C(0x401000);
    struct result warm=decode(iter,h,insn,data,length,address,mode);
    LARGE_INTEGER begin,end,freq;QueryPerformanceFrequency(&freq);QueryPerformanceCounter(&begin);uint64_t start=cpu();
    for (unsigned i=0;i<reps;++i) {
        struct result res=decode(iter,h,insn,data,length,address,mode);
        if (res.boundaries!=warm.boundaries || res.values!=warm.values || res.count!=warm.count || res.rejected!=warm.rejected) return 9;
    }
    uint64_t ticks=cpu()-start;QueryPerformanceCounter(&end);
    printf("%llu %llu %llu %llu %u %u %llu %llu\n",(unsigned long long)(end.QuadPart-begin.QuadPart),(unsigned long long)freq.QuadPart,
        (unsigned long long)ticks,(unsigned long long)(uintptr_t)module,warm.count,warm.rejected,(unsigned long long)warm.boundaries,(unsigned long long)warm.values);
    release(insn,1);close(&h);FreeLibrary(module);free(data);return 0;
}
