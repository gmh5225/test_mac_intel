#include <limits.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include "Mapping.h"
#include "utils.h"

static const name_map ppc[] = {
#include "arch/PowerPC/PPCGenCSAliasMnemMap.inc"
    {PPC_INS_ALIAS_SLWI, "slwi"},
    {PPC_INS_ALIAS_SRWI, "srwi"},
    {PPC_INS_ALIAS_SLDI, "sldi"},
    {PPC_INS_ALIAS_END, NULL},
};
static const name_map custom[] = {
    {17, "move"}, {23, "move.w"}, {29, "move,pt"},
    {31, "123456789abcdef"}, {0, "zero"}, {UINT_MAX, "negative"},
    {41, ""}, {43, "move"}, {47, "longerthan15characters"},
    {49, NULL}, {51, "unreachable"},
};
static unsigned long observations;
static void (*reference_alias)(MCInst *, const SStream *, const name_map *, int);

static unsigned first_hint(const name_map *names, unsigned count,
                           const char *name)
{
    for (unsigned i = 0; i < count && names[i].name; ++i)
        if (!strcmp(names[i].name, name))
            return i + 1;
    return 0;
}

static int check(const name_map *names, unsigned count, unsigned hint,
                 cs_arch arch, const char *text, bool is_alias)
{
    cs_struct handle = {0};
    cs_insn original = {0}, candidate = {0};
    MCInst mi = {0};
    SStream ss = {0};
    handle.arch = arch;
    mi.csh = &handle;
    mi.flat_insn = &original;
    mi.isAliasInstr = is_alias;
    original.alias_id = candidate.alias_id = 77;
    strcpy(ss.buffer, text);
    reference_alias(&mi, &ss, names, count);
    mi.flat_insn = &candidate;
    if (!map_try_alias_id_hint(&mi, &ss, names, hint))
        map_set_alias_id(&mi, &ss, names, count);
    ++observations;
    if (original.alias_id != candidate.alias_id) {
        fprintf(stderr, "hint mismatch arch=%u hint=%u alias=%u text=%s old=%llu new=%llu\n",
                arch, hint, is_alias, text, (unsigned long long)original.alias_id,
                (unsigned long long)candidate.alias_id);
        return 1;
    }
    return 0;
}

static int fixture(const name_map *names, unsigned count)
{
    const cs_arch archs[] = {CS_ARCH_PPC, CS_ARCH_AARCH64, CS_ARCH_RISCV,
                             CS_ARCH_SPARC, CS_ARCH_ARM};
    const char *suffixes[] = {"", " r0", "\tr0", ".suffix", ",pt r0", "_suffix"};
    char text[512];
    for (unsigned a = 0; a < ARR_SIZE(archs); ++a) {
        for (unsigned i = 0; i < count; ++i) {
            if (!names[i].name)
                continue;
            unsigned hint = first_hint(names, count, names[i].name);
            for (unsigned s = 0; s < ARR_SIZE(suffixes); ++s) {
                snprintf(text, sizeof(text), " \t%s%s", names[i].name, suffixes[s]);
                if (check(names, count, hint, archs[a], text, true) ||
                    check(names, count, hint, archs[a], text, false) ||
                    check(names, count, 0, archs[a], text, true) ||
                    check(names, count, 1, archs[a], text, true))
                    return 1;
            }
            size_t length = strlen(names[i].name);
            for (size_t j = 0; j < length; ++j) {
                strcpy(text, names[i].name);
                text[j] = 0;
                if (check(names, count, hint, archs[a], text, true))
                    return 1;
                for (unsigned c = 1; c < 256; ++c) {
                    strcpy(text, names[i].name);
                    text[j] = (char)c;
                    if (check(names, count, hint, archs[a], text, true))
                        return 1;
                }
            }
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
    if (!library)
        return 3;
    reference_alias = (void (*)(MCInst *, const SStream *, const name_map *, int))
        dlsym(library, "map_set_alias_id");
    if (!reference_alias)
        return 4;
    if (fixture(ppc, ARR_SIZE(ppc)) || fixture(custom, ARR_SIZE(custom)))
        return 1;
    /* With no alias, the hint path must not inspect stream/map/architecture. */
    MCInst mi = {0};
    if (map_try_alias_id_hint(&mi, NULL, NULL, 1))
        return 1;
    printf("Validated %lu hinted/original alias observations\n", observations);
    dlclose(library);
    return 0;
}
