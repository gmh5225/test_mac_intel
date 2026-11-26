#include <capstone/capstone.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
static uint64_t snapshot(csh h, const cs_insn *insn) {
    uint64_t hash = 14695981039346656037ULL;
    auto value = [&](uint64_t x) { hash = (hash ^ x) * 1099511628211ULL; };
    auto text = [&](const char *s) { while (*s) value(static_cast<unsigned char>(*s++)); value(0); };
    const auto *d = insn->detail;
    bool detail = d != nullptr;
    value(insn->id);
        value(insn->alias_id);
        value(insn->address);
        value(insn->size);
        for (unsigned i = 0; i != insn->size; ++i)
          value(insn->bytes[i]);
        text(insn->mnemonic);
        text(insn->op_str);
        value(insn->is_alias);
        value(insn->usesAliasDetails);
        value(insn->illegal);
        if (detail) {
          value(d->writeback);
          value(d->groups_count);
          for (unsigned i = 0; i < d->groups_count; ++i)
            value(d->groups[i]);
          value(d->regs_read_count);
          value(d->regs_write_count);
          for (unsigned i = 0; i < d->regs_read_count; ++i)
            value(d->regs_read[i]);
          for (unsigned i = 0; i < d->regs_write_count; ++i)
            value(d->regs_write[i]);
          cs_regs reads{}, writes{};
          uint8_t nr = 0, nw = 0;
          value(cs_regs_access(h, insn, reads, &nr, writes, &nw));
          value(nr);
          value(nw);
          for (unsigned i = 0; i < nr; ++i)
            value(reads[i]);
          for (unsigned i = 0; i < nw; ++i)
            value(writes[i]);
          const auto &x = d->x86;
          for (auto v : x.prefix)
            value(v);
          for (auto v : x.opcode)
            value(v);
          value(x.rex);
          value(x.rex2);
          value(x.addr_size);
          value(x.modrm);
          value(x.sib);
          value(x.disp);
          value(x.sib_index);
          value(x.sib_scale);
          value(x.sib_base);
          value(x.xop_cc);
          value(x.sse_cc);
          value(x.avx_cc);
          value(x.avx_sae);
          value(x.avx_rm);
          value(x.eflags);
          value(x.op_count);
          value(x.encoding.modrm_offset);
          value(x.encoding.disp_offset);
          value(x.encoding.disp_size);
          value(x.encoding.imm_offset);
          value(x.encoding.imm_size);
          for (unsigned i = 0; i < x.op_count; ++i) {
            const auto &o = x.operands[i];
            value(o.type);
            value(o.size);
            value(o.access);
            value(o.avx_bcast);
            value(o.avx_zero_opmask);
            if (o.type == X86_OP_REG)
              value(o.reg);
            if (o.type == X86_OP_IMM)
              value(o.imm);
            if (o.type == X86_OP_MEM) {
              value(o.mem.segment);
              value(o.mem.base);
              value(o.mem.index);
              value(o.mem.scale);
              value(o.mem.disp);
            }
          }
        }
    return hash;
}
struct Callback { csh handle; unsigned count; };
static size_t CAPSTONE_API change_text(const uint8_t *,size_t size,size_t offset,void *opaque) {
    auto *ctx=static_cast<Callback *>(opaque);
    ++ctx->count;
    if (cs_option(ctx->handle, CS_OPT_TEXT, ctx->count&1 ? CS_OPT_ON : CS_OPT_OFF)) std::exit(2);
    return offset<size ? 1 : 0;
}
int main() {
    csh h=0;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) || cs_option(h,CS_OPT_DETAIL,CS_OPT_ON)) return 1;
    auto *rec=cs_malloc(h); if (!rec || !rec->detail) return 1;
    auto *stored=rec->detail;
    Callback ctx{h,0}; cs_opt_skipdata skip{".byte",change_text,&ctx};
    if (cs_option(h,CS_OPT_SKIPDATA_SETUP,reinterpret_cast<uintptr_t>(&skip))) return 1;
    const unsigned modes[]={CS_MODE_16,CS_MODE_32,CS_MODE_64,CS_MODE_32|CS_MODE_X86_AMD,
        CS_MODE_64|CS_MODE_X86_INTEL,CS_MODE_16|CS_MODE_64,CS_MODE_X86_AMD|CS_MODE_X86_INTEL};
    const uint8_t data[][10]={{0x40,0x90},{0x66,0xb8,0x78,0x56,0x34,0x12},{0x89,0x45,0xf0},
        {0xc5,0xf8,0x77},{0x62,0xf1,0x7c,0x48,0x58,0xc1},{0xeb,0xfe},{0x0f},{0x8b,0x05,1,2,3,4},
        {0xc4,0xe3,0x7b,0xf0,0xc0,1},{0xe8,0,0,0,0}};
    const size_t sizes[]={2,6,3,3,6,2,1,6,6,5};
    uint64_t total=0,accepted=0,digest=14695981039346656037ull;
    auto value=[&](uint64_t x){digest=(digest^x)*1099511628211ull;};
    for (unsigned turn=0;turn<2;++turn) for (unsigned state=0;state<7*2*3*2;++state) {
        const unsigned opt=turn ? 83-state : (state*29)%84;
        const unsigned mode=modes[opt%7], text=(opt/7)%2, detail=(opt/14)%3, ds=detail==2 ? CS_OPT_DETAIL_REAL : detail==1 ? CS_OPT_ON : CS_OPT_OFF;
        if(cs_option(h,CS_OPT_DETAIL,CS_OPT_OFF)) return 3;
        if(turn) {value(cs_option(h,CS_OPT_MODE,mode));value(cs_option(h,CS_OPT_TEXT,text?CS_OPT_ON:CS_OPT_OFF));value(cs_option(h,CS_OPT_DETAIL,ds));}
        else {value(cs_option(h,CS_OPT_DETAIL,ds));value(cs_option(h,CS_OPT_TEXT,text?CS_OPT_ON:CS_OPT_OFF));value(cs_option(h,CS_OPT_MODE,mode));}
        value(cs_option(h,CS_OPT_SKIPDATA,opt/42?CS_OPT_ON:CS_OPT_OFF));
        for(unsigned f=0;f<10;++f) for(size_t length=0;length<=sizes[f];++length){
            const uint8_t *code=data[f];size_t size=length;uint64_t address=UINT64_MAX-3;
            *rec={};rec->detail=stored;std::memset(stored,0,sizeof(*stored));
            const bool ok=cs_disasm_iter(h,&code,&size,&address,rec);++total;accepted+=ok;
            if(rec->detail!=stored || code!=data[f]+(length-size) || address!=(UINT64_MAX-3)+(length-size)) return 4;
            value(ok);value(size);value(address);value(cs_errno(h));
            if(ok){auto copy=*rec;if(!detail || !rec->id) copy.detail=nullptr;value(snapshot(h,&copy));}
        }
    }
    if(!ctx.count || !accepted || accepted==total) return 5;
    printf("%llu %llu %u %llu\n",(unsigned long long)total,(unsigned long long)accepted,ctx.count,(unsigned long long)digest);
    cs_free(rec,1);cs_close(&h);
}
