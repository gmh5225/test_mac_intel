#include <valgrind/callgrind.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>
struct RecordCohort { uint64_t offset; unsigned kind; };
static std::vector<RecordCohort> cohorts;
static const uint8_t *image_start;
static size_t position;
static unsigned selected;
static bool collecting,armed;
static unsigned long long selected_visits;
static void profile_begin(const uint8_t *start) {
    const char *path=std::getenv("CG_COHORT_FILE");
    if(!path)return;
    std::ifstream in(path,std::ios::binary);if(!in)std::abort();
    uint64_t offset;
    while(in.read(reinterpret_cast<char *>(&offset),sizeof(offset))) {
        int tag=in.get();if(tag<0||tag>11)std::abort();cohorts.push_back({offset,unsigned(tag)});
    }
    if(!in.eof()||cohorts.empty())std::abort();
    image_start=start;selected=std::strtoul(std::getenv("CG_COHORT"),nullptr,10);armed=true;
    CALLGRIND_ZERO_STATS;
}
extern "C" __attribute__((noinline)) void profile_instruction(const uint8_t *p) {
    if(!armed)return;
    if(position==cohorts.size())std::abort();
    const RecordCohort &r=cohorts[position++];
    if(r.offset!=static_cast<uint64_t>(p-image_start))std::abort();
    bool current=selected==12 || selected==r.kind;
    selected_visits+=current;
    if(current!=collecting){collecting=current;CALLGRIND_TOGGLE_COLLECT;}
}
static void profile_end() {
    if(!armed)return;
    if(collecting){CALLGRIND_TOGGLE_COLLECT;collecting=false;}
    if(position!=cohorts.size())std::abort();
    armed=false;std::fprintf(stderr,"cohort-visits %zu %llu\n",position,selected_visits);
}
