#define main baseline_record_corpus_main
#include "public-records.cpp"
#undef main
#include <array>

struct Cache {
    Api &api;
    cs_insn *value;
    explicit Cache(Api &a) : api(a), value(a.symbol<decltype(&cs_malloc)>("cs_malloc")(a.handle)) {
        if (!value) throw std::runtime_error("cs_malloc");
    }
    ~Cache() { api.release(value, 1); }
    Cache(const Cache &) = delete;
    void reset() {
        auto *detail = value->detail;
        std::memset(value, 0, sizeof(*value));
        value->detail = detail;
        std::memset(value->bytes, 0x5a, sizeof(value->bytes));
        std::memset(value->mnemonic, 0x5a, sizeof(value->mnemonic));
        std::memset(value->op_str, 0x5a, sizeof(value->op_str));
        if (detail) std::memset(detail, 0, sizeof(*detail));
    }
};

int main(int argc, char **argv) {
    if (argc != 3) return 1;
    Api old(argv[1], CS_MODE_32), updated(argv[2], CS_MODE_32);
    auto set = [&](cs_opt_type opt, size_t val) {
        return old.option(old.handle, opt, val) == updated.option(updated.handle, opt, val);
    };
    if (!set(CS_OPT_DETAIL, CS_OPT_ON)) return 2;
    Cache retained_old(old), retained_new(updated);
    if (!retained_old.value->detail || !retained_new.value->detail) return 3;
    const std::array<std::array<uint8_t, 8>, 8> codes{{
        {0x48,0x8b,0xc1}, {0x67,0x8b,0x04,0x24}, {0xc5,0xf8,0x77},
        {0x66,0x48,0xd9,0x30}, {0x0f,0x0b}, {0x62,0xf1,0x7d,0x48,0xfe,0xd9},
        {0xc5,0xdc,0x59,0xc4}, {0xc4,0,0,0xff}
    }};
    const size_t modes[] = {CS_MODE_16,CS_MODE_32,CS_MODE_64,CS_MODE_64|CS_MODE_X86_INTEL,
                            CS_MODE_32|CS_MODE_X86_AMD,CS_MODE_X86_INTEL|CS_MODE_X86_AMD};
    const size_t details[] = {CS_OPT_ON,CS_OPT_DETAIL_REAL,CS_OPT_OFF,CS_OPT_DETAIL_REAL,
                              CS_OPT_DETAIL_REAL|CS_OPT_ON,CS_OPT_OFF};
    unsigned count = 0;
    for (int pass=0; pass<2; ++pass) for (size_t mode : modes) {
        if (!set(CS_OPT_MODE, mode)) return 4;
        for (auto flags : details) for (auto text : {CS_OPT_ON,CS_OPT_OFF})
            for (auto skip : {CS_OPT_OFF,CS_OPT_ON}) {
                if (!set(CS_OPT_TEXT,text) || !set(CS_OPT_DETAIL,flags) || !set(CS_OPT_SKIPDATA,skip)) return 5;
                Cache fresh_old(old), fresh_new(updated);
                for (const auto &bytes : codes) for (size_t n=0; n<=bytes.size(); ++n)
                    for (bool retained : {false,true}) {
                        Cache &a = retained ? retained_old : fresh_old;
                        Cache &b = retained ? retained_new : fresh_new;
                        a.reset(); b.reset();
                        auto *ad = a.value->detail, *bd = b.value->detail;
                        const uint8_t *pa = bytes.data(), *pb = pa;
                        size_t na = n, nb = n;
                        uint64_t ia = UINT64_MAX-3, ib = ia;
                        const bool va = old.iter(old.handle,&pa,&na,&ia,a.value);
                        const bool vb = updated.iter(updated.handle,&pb,&nb,&ib,b.value);
                        if (a.value->detail!=ad || b.value->detail!=bd || bool(ad)!=bool(bd)) return 6;
                        b.value->detail = ad;
                        const bool equal = std::memcmp(a.value,b.value,sizeof(cs_insn))==0;
                        b.value->detail = bd;
                        if (va!=vb || pa!=pb || na!=nb || ia!=ib || !equal ||
                            old.error(old.handle)!=updated.error(updated.handle) ||
                            (ad && std::memcmp(ad,bd,sizeof(cs_detail)))) {
                            std::fprintf(stderr,"pass=%d mode=%zu flags=%zu text=%d skip=%d retained=%d index=%zu length=%zu\n",
                                         pass,mode,flags,text,skip,retained,size_t(&bytes-&codes[0]),n);
                            return 7;
                        }
                        ++count;
                    }
            }
    }
    std::printf("%u\n",count);
    return 0;
}
