// Benchmark-only lifecycle workload using the same decoding and detail consumers.
#define main long_stream_main
#include "compare.cpp"
#undef main

struct Span { size_t offset, length; };

static cs_mode cs_bits(unsigned bits) {
  if (bits == 64) return CS_MODE_64;
  if (bits == 32) return CS_MODE_32;
  if (bits == 16) return CS_MODE_16;
  throw std::runtime_error("invalid bitness");
}

static std::vector<uint8_t> load_bytes(const char *path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("section unavailable");
  return {std::istreambuf_iterator<char>(input), {}};
}

static void save_spans(const char *input, unsigned bits, unsigned width, const char *output) {
  auto bytes = load_bytes(input);
  csh handle = 0;
  if (cs_open(CS_ARCH_X86, cs_bits(bits), &handle) != CS_ERR_OK)
    throw std::runtime_error("span decoder");
  cs_option(handle, CS_OPT_TEXT, CS_OPT_OFF);
  cs_insn *insn = cs_malloc(handle);
  if (!insn) throw std::bad_alloc();
  const uint8_t *cursor = bytes.data();
  size_t left = bytes.size(), start = 0;
  uint64_t ip = 0x100000;
  unsigned accepted = 0;
  std::vector<Span> all;
  while (left) {
    if (!X86_disasmIter(handle, &cursor, &left, &ip, insn)) {
      ++cursor; --left; ++ip;
      accepted = 0;
    } else {
      ++accepted;
      if (accepted < width) continue;
      all.push_back({start, bytes.size()-left-start});
      accepted = 0;
    }
    start = bytes.size()-left;
  }
  cs_free(insn,1);
  cs_close(&handle);
  if (all.size() < 32) throw std::runtime_error("insufficient eligible windows");
  std::ofstream file(output);
  for (size_t i=0; i<32; ++i) {
    const auto span=all[i*(all.size()-1)/31];
    file << span.offset << ' ' << span.length << '\n';
  }
  if (!file) throw std::runtime_error("could not save windows");
}

int main(int argc, char **argv) {
  if (argc==6 && std::string(argv[1])=="spans") {
    save_spans(argv[2],std::stoul(argv[3]),std::stoul(argv[4]),argv[5]);
    return 0;
  }
  if (argc!=7) return 2;
  const bool iced=std::string(argv[1])=="iced";
  const unsigned bits=std::stoul(argv[2]), repeats=std::stoul(argv[3]);
  const bool only_open=std::string(argv[4])=="open";
  auto bytes=load_bytes(argv[5]);
  std::ifstream input(argv[6]);
  std::vector<Span> spans;
  Span span;
  while (input >> span.offset >> span.length) {
    if (span.offset>bytes.size() || !span.length || span.length>bytes.size()-span.offset)
      throw std::runtime_error("invalid window");
    spans.push_back(span);
  }
  if (spans.size()!=32 || (iced && only_open)) return 3;
  Result aggregate;
  const auto wall=std::chrono::steady_clock::now();
  const auto cpu=process_cpu_ns();
  for (unsigned i=0; i<repeats; ++i) for (auto s : spans) {
    if (only_open) {
      csh h=0;
      if(cs_open(CS_ARCH_X86,cs_bits(bits),&h)!=CS_ERR_OK || cs_close(&h)!=CS_ERR_OK)
        throw std::runtime_error("opening or closing a handle");
      ++aggregate.values;
      continue;
    }
    Result result;
    if (iced) {
      void *state=iced_create(bits,2);
      iced_run(state,bytes.data()+s.offset,s.length,1,&result);
      iced_destroy(state);
    } else {
      result=capstone_run(bytes.data()+s.offset,s.length,bits,2,1);
    }
    aggregate.instructions+=result.instructions;
    aggregate.rejected+=result.rejected;
    aggregate.values+=result.values;
    aggregate.boundaries=(aggregate.boundaries^result.boundaries)*1099511628211ULL;
  }
  const auto elapsed=process_cpu_ns()-cpu;
  auto ns=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-wall).count();
  std::printf("{\"instructions\":%llu,\"rejected\":%llu,\"boundary_hash\":\"%016llx\",\"value_hash\":\"%016llx\",\"window_count\":%llu,\"cpu_ns\":%.0f,\"wall_ns\":%lld}\n",
    (unsigned long long)aggregate.instructions,(unsigned long long)aggregate.rejected,
    (unsigned long long)aggregate.boundaries,(unsigned long long)aggregate.values,
    (unsigned long long)repeats*spans.size(),elapsed,(long long)ns);
}
