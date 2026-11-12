#include <valgrind/callgrind.h>
extern "C" { unsigned cs_probe_memory_variant; }
int main(int argc, char **argv) {
    if (argc != 6) return 2;
    unsigned plan = std::stoul(argv[1]), which = std::stoul(argv[2]);
    API api;
    Session session(api, std::stoul(argv[3]), std::stoul(argv[4]));
    std::ifstream stream(argv[5],std::ios::binary);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(stream)),{});
    if (bytes.empty()) return 3;
    auto trial = [&](unsigned variant, unsigned repetitions) {
        cs_probe_memory_variant = variant;
        return run(session, bytes, repetitions);
    };
    const auto reference = trial(0,1);
    if (!equal(reference,trial(1,1))) return 4;
    if (plan == 3) {
        cs_probe_memory_variant = which;
        CALLGRIND_START_INSTRUMENTATION;
        CALLGRIND_ZERO_STATS;
        auto result = run(session, bytes, 1);
        CALLGRIND_STOP_INSTRUMENTATION;
        if (!equal(reference,result)) return 5;
        std::printf("{\"count\":%llu,\"boundary\":%llu,\"value\":%llu}\n",(unsigned long long)result.instructions,(unsigned long long)result.boundaries,(unsigned long long)result.values);
        return 0;
    }
    double start = process_cpu_ns();
    if (!equal(reference,trial(0,1))) return 6;
    unsigned repeat=std::max(1u,unsigned(std::ceil(80000000.0/std::max(1.0,process_cpu_ns()-start))));
    const auto expected=trial(0,repeat);
    if(!equal(expected,trial(1,repeat)))return 7;
    std::printf("{\"count\":%llu,\"repeats\":%u,\"ratios\":[",(unsigned long long)reference.instructions,repeat);
    for(unsigned cycle=0;cycle<11;cycle++) {
        double ticks[2]={0,0};
        for(unsigned j=0;j<4;j++) {
            unsigned side=(j==1 || j==2)^(cycle&1)^which;
            unsigned variant=plan==0 ? side : plan-1;
            cs_probe_memory_variant=variant;
            double begin=process_cpu_ns();
            auto result=run(session,bytes,repeat);
            ticks[side]+=process_cpu_ns()-begin;
            if(!equal(expected,result)) return 8;
        }
        std::printf("%s%.9f",cycle?",":"",ticks[0]/ticks[1]);
    }
    std::puts("]}");
}
