#define main original_comparison_main
#include "trial-compare.cpp"
#undef main
#include <memory>

struct SavedRecord {
    unsigned id;
    cs_detail detail;
};
struct Measurements { uint64_t cpu,wall,count; };
static uint64_t nanoseconds(clockid_t clock)
{
    timespec t{};
    check(clock_gettime(clock,&t)==0,"clock");
    return uint64_t(t.tv_sec)*1000000000ULL+uint64_t(t.tv_nsec);
}
static Measurements measure(Session &s, const std::vector<SavedRecord> &records, unsigned repeats)
{
    cs_regs read,write;
    uint8_t nr,nw;
    cs_insn out{};
    uint64_t count=0;
    const uint64_t wall=nanoseconds(CLOCK_MONOTONIC),cpu=nanoseconds(CLOCK_PROCESS_CPUTIME_ID);
    for (unsigned i=0;i<repeats;++i) {
        for (const auto &item:records) {
            out.id=item.id;
            out.detail=const_cast<cs_detail *>(&item.detail);
            check(s.api.regs(s.h,&out,read,&nr,write,&nw)==CS_ERR_OK,"regs");
            count+=nr+nw;
        }
    }
    uint64_t elapsed=nanoseconds(CLOCK_PROCESS_CPUTIME_ID)-cpu;
    return {elapsed,nanoseconds(CLOCK_MONOTONIC)-wall,count};
}
int main(int argc,char **argv)
{
    if (argc!=8) return 2;
    Api original(argv[1]),forward(argv[2]),backward(argv[3]);
    cs_mode mode=std::atoi(argv[6])==64 ? CS_MODE_64 : CS_MODE_32;
    Session source(original,CS_ARCH_X86,mode),one(forward,CS_ARCH_X86,mode),two(backward,CS_ARCH_X86,mode);
    for (auto *s:{&source,&one,&two}) s->set(CS_OPT_DETAIL,CS_OPT_ON);
    std::ifstream input(argv[4],std::ios::binary),ranges(argv[5]);
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input),{}};
    check(!bytes.empty()&&bool(ranges),"input");
    const unsigned expected=std::strtoul(argv[7],nullptr,10),stride=(expected+8191)/8192;
    check(stride>0,"stride");
    cs_insn *insn=original.alloc(source.h);check(insn&&insn->detail,"allocate");
    std::vector<SavedRecord> records;records.reserve(std::min(8192u,expected));
    unsigned accepted=0;size_t start,n;uint64_t ip;
    while (ranges>>start>>n>>ip) {
        check(n&&start<=bytes.size()&&n<=bytes.size()-start,"range");
        const uint8_t *cursor=bytes.data()+start;
        while(n) {
            if (!original.next(source.h,&cursor,&n,&ip,insn)) {++cursor;--n;++ip;continue;}
            if (accepted++%stride==0) records.push_back({insn->id,*insn->detail});
        }
    }
    original.free(insn,1);
    check(accepted==expected&&records.size()==(expected+stride-1)/stride,"population");
    std::array<Session *,4> handles{&source,&one,&two,&source};
    std::array<unsigned,4> order{0,1,2,3};
    const auto reference=measure(source,records,1);
    unsigned repeats=unsigned(std::max<uint64_t>(1,(12000000+reference.cpu-1)/reference.cpu));
    printf("%u %zu %u %u %llu\n",accepted,records.size(),stride,repeats,(unsigned long long)reference.count);
    std::mt19937 rng(738512+expected);
    for (unsigned round=0;round<35;++round) {
        std::shuffle(order.begin(),order.end(),rng);
        std::array<std::array<uint64_t,2>,4> sum{};
        for (unsigned k=0;k<8;++k) {
            const unsigned label=order[k<4?k:7-k];
            const auto timing=measure(*handles[label],records,repeats);
            check(timing.count==reference.count*repeats,"query result");
            sum[label][0]+=timing.cpu;sum[label][1]+=timing.wall;
        }
        for (unsigned k=0;k<4;++k) printf("%llu %llu%c",(unsigned long long)sum[k][0],(unsigned long long)sum[k][1],k==3?'\n':' ');
    }
    return 0;
}
