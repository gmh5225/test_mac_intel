#define main general_oracle_main
#include "trial-compare.cpp"
#undef main
#include <chrono>
struct SavedRecord {
    uint64_t ordinal;
    cs_insn insn;
    cs_detail detail;
};
struct Sample {
    std::vector<SavedRecord> examples;
    std::mt19937_64 rng{182049};
    uint64_t seen{};
    void observe(const cs_insn &insn, uint64_t ordinal) {
        size_t at = seen++;
        if (at >= 512) {
            at = std::uniform_int_distribution<uint64_t>(0, at)(rng);
            if (at >= 512) return;
        } else examples.emplace_back();
        auto &row = examples[at];
        row.ordinal = ordinal;
        std::memcpy(&row.insn,&insn,sizeof insn);
        std::memcpy(&row.detail,insn.detail,sizeof row.detail);
        row.insn.detail = nullptr;
    }
};
static uint64_t ns(clockid_t id) {
    timespec t{};
    check(clock_gettime(id,&t)==0,"clock");
    return uint64_t(t.tv_sec)*1000000000+t.tv_nsec;
}
int main(int argc,char **argv) {
    if (argc!=7) return 2;
    Api base(argv[1]), a(argv[2]), b(argv[3]);
    const cs_mode mode=std::stoi(argv[6])==64 ? CS_MODE_64 : CS_MODE_32;
    Session first(base,CS_ARCH_X86,mode), second(a,CS_ARCH_X86,mode), third(b,CS_ARCH_X86,mode);
    for (Session *s:{&first,&second,&third}) s->set(CS_OPT_DETAIL,CS_OPT_ON);
    std::ifstream file(argv[4],std::ios::binary),spans(argv[5]);
    std::vector<uint8_t> input{std::istreambuf_iterator<char>(file),{}};
    check(!input.empty() && bool(spans),"inputs");
    cs_insn *insn=base.alloc(first.h);
    check(insn,"insn");
    std::array<Sample,3> samples;
    size_t start,length; uint64_t ip,serial=0;
    while (spans>>start>>length>>ip) {
        check(start<=input.size() && length<=input.size()-start,"span");
        const uint8_t *p=input.data()+start;
        while (length) {
            if (!base.next(first.h,&p,&length,&ip,insn)) { ++p; --length; ++ip; continue; }
            auto &x=insn->detail->x86;
            bool implicit_only=x.op_count==0 || (x.op_count==1 && x.operands[0].type==X86_OP_IMM);
            samples[0].observe(*insn,serial);
            samples[implicit_only?1:2].observe(*insn,serial++);
        }
    }
    base.free(insn,1);
    unsigned group=0;
    for (auto &sample:samples) {
        auto &records=sample.examples;
        check(!records.empty(),"empty group");
        std::sort(records.begin(),records.end(),[](const auto &a,const auto &b){return a.ordinal<b.ordinal;});
        uint64_t identity=0;
        for (auto &v:records) {
            v.insn.detail=&v.detail;
            identity=(identity^v.ordinal)*1099511628211ULL+v.insn.address+v.insn.id;
            cs_regs br,bw;uint8_t nr{},nw{};
            std::memset(br,0x75,sizeof br);std::memset(bw,0x8a,sizeof bw);
            check(!base.regs(first.h,&v.insn,br,&nr,bw,&nw),"baseline query");
            for (Session *s:{&second,&third}) {
                cs_regs rr,rw;uint8_t x{},y{};
                std::memset(rr,0x75,sizeof rr);std::memset(rw,0x8a,sizeof rw);
                check(!s->api.regs(s->h,&v.insn,rr,&x,rw,&y) && x==nr && y==nw &&
                    !std::memcmp(br,rr,sizeof br) && !std::memcmp(bw,rw,sizeof bw),"query output");
            }
        }
        auto bench=[&](Session &s,unsigned repeats) {
            uint64_t sum=0, cpu=ns(CLOCK_PROCESS_CPUTIME_ID), wall=ns(CLOCK_MONOTONIC);
            for (unsigned i=0;i<repeats;++i) for (const auto &v:records) {
                cs_regs rr,rw;uint8_t nr,nw;
                const auto status=s.api.regs(s.h,&v.insn,rr,&nr,rw,&nw);
                check(status==CS_ERR_OK,"timed query");
                sum+=nr+nw+(nr?rr[nr-1]:0)+(nw?rw[nw-1]:0);
            }
            return std::array<uint64_t,3>{ns(CLOCK_PROCESS_CPUTIME_ID)-cpu,ns(CLOCK_MONOTONIC)-wall,sum};
        };
        auto probe=bench(first,16);
        const unsigned repeats=std::max<uint64_t>(16,std::min<uint64_t>(8192,16*4000000/std::max<uint64_t>(probe[0],1)));
        const uint64_t expected=bench(first,repeats)[2];
        const char *names[]={"base","duplicate","candidate","outlined"};
        Session *sessions[]={&first,&first,&second,&third};
        std::array<int,4> order{0,1,2,3};
        std::mt19937 random(22937+group);
        for (unsigned block=0;block<17;++block) {
            std::shuffle(order.begin(),order.end(),random);
            uint64_t total[4][2]{};
            for (int i=0;i<8;++i) {
                int k=order[i<4 ? i : 7-i];
                auto result=bench(*sessions[k],repeats);
                check(result[2]==expected,"timed result");
                total[k][0]+=result[0];total[k][1]+=result[1];
            }
            for (unsigned i=0;i<4;++i)
                std::printf("%u %u %s %" PRIu64 " %zu %" PRIu64 " %u %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
                    group,block,names[i],sample.seen,records.size(),identity,repeats,total[i][0],total[i][1],expected);
        }
        ++group;
    }
}
