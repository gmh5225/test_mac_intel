extern "C" size_t iced_trace(const uint8_t *, size_t, uint64_t, uint8_t *);

struct Span { size_t offset, size; uint64_t ip; };
static void add_result(Result &total,const Result &span,const Span &range) {
  total.instructions += span.instructions; total.rejected += span.rejected;
  total.boundaries = ((total.boundaries ^ range.ip) * 1099511628211ULL ^ span.boundaries) * 1099511628211ULL;
  total.values += span.values;
}

int main(int argc,char **argv) {
  if(argc!=6) return 2;
  std::string engine=argv[1];
  unsigned mode=std::stoul(argv[2]), reps=std::stoul(argv[3]);
  if (mode>2 || !reps) return 2;
  std::ifstream file(argv[4],std::ios::binary), table(argv[5]);
  std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file), {}};
  std::vector<Span> spans;
  Span span{};
  while(table>>span.offset>>span.size>>span.ip) {
    if(!span.size || span.offset>bytes.size() || span.size>bytes.size()-span.offset) return 3;
    spans.push_back(span);
  }
  if(!table.eof() || spans.empty()) return 3;
  csh handle=0;
  if(cs_open(CS_ARCH_X86,CS_MODE_64,&handle)!=CS_ERR_OK ||
     cs_option(handle,CS_OPT_DETAIL,mode==2 ? CS_OPT_ON : CS_OPT_OFF)!=CS_ERR_OK ||
     cs_option(handle,CS_OPT_TEXT,mode ? CS_OPT_ON : CS_OPT_OFF)!=CS_ERR_OK) return 4;
  cs_insn *insn=cs_malloc(handle);
  void *iced=iced_create(64,mode);
  if(!insn || !iced) return 5;
  if(engine=="audit") {
    for(auto f : spans) {
      auto ptr=bytes.data()+f.offset;
      std::vector<uint8_t> expected(f.size), actual;
      expected.resize(iced_trace(ptr,f.size,f.ip,expected.data()));
      const uint8_t *cursor=ptr;
      size_t left=f.size; uint64_t ip=f.ip;
      while(left) {
        bool ok=cs_disasm_iter(handle,&cursor,&left,&ip,insn);
        actual.push_back(ok ? (uint8_t)insn->size : 0);
        if(!ok) {++cursor; --left; ++ip;}
      }
      size_t i=0, offset=0;
      while(i<actual.size() && i<expected.size() && actual[i]==expected[i]) {
        offset+=actual[i] ? actual[i] : 1; ++i;
      }
      if(actual==expected) offset=f.size;
      std::printf("%zu\t%zu\t%llu\t%zu\t%zu\t%zu\n",f.offset,f.size,
                  (unsigned long long)f.ip,actual.size(),expected.size(),offset);
    }
  } else {
    if(engine!="capstone" && engine!="iced") return 6;
    auto run=[&](unsigned n) {
      Result all;
      for(unsigned i=0;i<n;++i) for(auto f:spans) {
        Result row;
        if(engine=="capstone") row=cs_span(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);
        else iced_run(iced,bytes.data()+f.offset,f.size,1,f.ip,&row);
        add_result(all,row,f);
      }
      return all;
    };
#ifdef _WIN32
    DWORD_PTR mask,system;
    if(!GetProcessAffinityMask(GetCurrentProcess(),&mask,&system) || !mask ||
       !SetThreadAffinityMask(GetCurrentThread(),mask & -mask)) return 7;
#endif
    Result warm=run(1);
    auto start=std::chrono::steady_clock::now();
#ifdef _WIN32
    ULONG64 t0,t1; if(!QueryThreadCycleTime(GetCurrentThread(),&t0)) return 7;
#else
    double t0=process_cpu_ns();
#endif
    Result timed=run(reps);
#ifdef _WIN32
    if(!QueryThreadCycleTime(GetCurrentThread(),&t1)) return 7;
#else
    double t1=process_cpu_ns();
#endif
    auto duration=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-start).count();
    if(warm.instructions*reps!=timed.instructions || warm.rejected*reps!=timed.rejected) return 8;
    std::printf("%llu %lld %llu %llu %llu %llu\n",(unsigned long long)(t1-t0),(long long)duration,
       (unsigned long long)timed.instructions,(unsigned long long)timed.rejected,
       (unsigned long long)timed.boundaries,(unsigned long long)timed.values);
  }
  iced_destroy(iced); cs_free(insn,1); cs_close(&handle);
}
