#define main original_entry
#include "single.cpp"
#undef main

extern "C" void benchmark_set_hex_variant(int);

int main(int argc, char **argv) {
  try {
    if (argc != 4)
      throw std::runtime_error("selector mode input");
    const unsigned selector = std::stoul(argv[1]);
    const unsigned mode = std::stoul(argv[2]);
    API api;
    Session session(api, selector, mode);
    std::ifstream file(argv[3], std::ios::binary);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), {});
    if (bytes.empty() || mode < 1 || mode > 2)
      throw std::runtime_error("input/mode");
    benchmark_set_hex_variant(0);
    unsigned repeats = 1;
    double elapsed;
    do {
      const double start = process_cpu_ns();
      run(session, bytes, repeats);
      elapsed = process_cpu_ns() - start;
      if (elapsed < 10000000)
        repeats *= 2;
    } while (elapsed < 10000000);
    repeats = std::max(1U, unsigned(std::ceil(repeats * 80000000 / elapsed)));
    const Result expected = run(session, bytes, repeats);
    benchmark_set_hex_variant(1);
    if (!equal(expected, run(session, bytes, repeats)))
      throw std::runtime_error("variant output mismatch");
    for (unsigned cycle = 0; cycle < 16; ++cycle) {
      for (unsigned ordinal = 0; ordinal < 4; ++ordinal) {
        const unsigned variant = ((ordinal == 1 || ordinal == 2) ^ (cycle & 1));
        benchmark_set_hex_variant(variant);
        run(session, bytes, 1);
        const double start = process_cpu_ns();
        const auto wall = std::chrono::steady_clock::now();
        const Result result = run(session, bytes, repeats);
        elapsed = process_cpu_ns() - start;
        const double duration = std::chrono::duration<double, std::nano>(
                                    std::chrono::steady_clock::now() - wall).count();
        if (!equal(expected, result))
          throw std::runtime_error("sample output mismatch");
        std::printf("{\"cycle\":%u,\"ordinal\":%u,\"variant\":%u,"
                    "\"repeats\":%u,\"cpu_ns\":%.0f,\"wall_ns\":%.0f,"
                    "\"instructions\":%llu,\"rejected\":%llu,"
                    "\"boundaries\":%llu,\"values\":%llu}\n",
                    cycle, ordinal, variant, repeats, elapsed, duration,
                    (unsigned long long)result.instructions,
                    (unsigned long long)result.rejected,
                    (unsigned long long)result.boundaries,
                    (unsigned long long)result.values);
      }
      std::fflush(stdout);
    }
    return 0;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
  }
}
