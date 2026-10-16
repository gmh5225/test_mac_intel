// Private, cache-free reconstruction of the captured graph's observable metadata.
// No original executable prefix, serialized bytecode, or prelinked cache is used.
#define main rawStorageAdapterMain
#include "raw-graph-linux-adapter.cpp"
#undef main

struct GraphLocation { uint64_t sectionSizeField, base, size, table, count; };
GraphLocation locateGraph(const Bytes &b) {
  const auto n=locateNativeGraph(b);const auto footer=n.base+n.size-48;
  return {n.sectionSizeField,n.base,n.size,number(b,footer+8,4),number(b,footer+12,4)/52};
}

int main(int argc, char **argv) try {
  require(argc == 8, "map raw-input fresh-output entry startup-count default-flags jit-scale");
  const auto rows = mapping(argv[1]);
  const auto startup = decimal(argv[5]);
  const auto defaults = decimal(argv[6]);
  const auto jitScale = decimal(argv[7]);
  require(startup <= rows.size() && defaults <= 15, "graph options range");
  require(jitScale == 1 || jitScale == 8, "unqualified JIT policy");
  const auto selected = std::find_if(rows.begin(), rows.end(), [&](const Row &r) {
    return r.name == argv[4];
  });
  require(selected != rows.end() && selected->loader == 1, "missing JavaScript entry");

  // The prior adapter validates the independently compiled container and every
  // embedded body, then restores the qualified text module storage encodings.
  const fs::path intermediate = std::string(argv[3]) + ".text-storage-only";
  patch(rows, argv[2], intermediate);
  auto b = bytes(intermediate);
  const auto g = locateGraph(b);
  const auto oldFooter = g.base + g.size - 48;
  const auto oldTail = g.table + g.count * 52;
  require(number(b, oldFooter + 24, 4) == 0 &&
              number(b, oldFooter + 20, 4) == oldTail + g.count * 4 + 8 &&
              g.size - 48 == oldTail + g.count * 4 + 9,
          "only an empty compile argv is qualified");
  std::map<std::string, Bytes> records;
  for (uint64_t i = 1; i < g.count; ++i) {
    const auto at = g.base + g.table + i * 52;
    records.emplace(text(b, g.base + number(b, at, 4), number(b, at + 4, 4)),
                    Bytes(b.begin() + at, b.begin() + at + 52));
    require(number(b, g.base + oldTail + i * 4, 4) == 0,
            "unexpected source hash on raw asset");
  }
  Bytes tail;
  unsigned javascript = 0, native = 0;
  for (const auto &r : rows) {
    auto record = records.at(r.name);
    const auto co = number(record, 8, 4), cn = number(record, 12, 4);
    require(cn == r.size && hash(b.data() + g.base + co, cn) == r.sha,
            "retained source/storage bytes changed");
    if (r.loader == 1) {
      // The project source is UTF-8. Only the proven identity projection to
      // captured Latin-1 storage is admitted; no non-ASCII recoding is guessed.
      require(r.encoding == 1 && std::all_of(b.begin() + g.base + co,
                  b.begin() + g.base + co + cn, [](auto c) { return c < 128; }),
              "JavaScript storage requires proven ASCII Latin-1 identity");
      ++javascript;
    }
    native += r.loader == 10;
    record[48] = r.encoding;
    record[49] = r.loader;
    record[50] = r.format;
    record[51] = r.side;
    tail.insert(tail.end(), record.begin(), record.end());
  }
  const auto append = [&](uint64_t value, unsigned width) {
    const auto at = tail.size();
    tail.resize(at + width);
    set(tail, at, value, width);
  };
  // A zero source hash means compute it from source. These are cache-free
  // records, so no cached source/hash association is reused.
  tail.resize(tail.size() + rows.size() * 4, 0);
  append(0, 4); // No builtin bytecode.
  append(startup, 4);
  if (jitScale == 8) {
    append(2, 4); // RuntimeOptions::HAS_JIT_POLICY.
    append(0x41000000, 4); // IEEE-754 f32 8.0.
  }
  const auto argsOffset = g.table + tail.size();
  append(0, 1); // Empty compile argv, with its required terminator.
  const auto dataSize = g.table + tail.size();
  append(dataSize, 8);
  append(g.table, 4);
  append(rows.size() * 52, 4);
  append(selected - rows.begin(), 4);
  append(argsOffset, 4);
  append(0, 4);
  const auto flags = 0x170 | defaults | (jitScale == 8 ? 0x1000 : 0);
  append(flags, 4);
  const std::string trailer = "\n---- Bun! ----\n";
  tail.insert(tail.end(), trailer.begin(), trailer.end());
  const auto newSize = g.table + tail.size();
  require(newSize <= g.size, "metadata exceeds the compiled graph allocation");
  std::fill(b.begin() + g.base + g.table, b.begin() + g.base + g.size, 0);
  std::copy(tail.begin(), tail.end(), b.begin() + g.base + g.table);
  set(b, g.base - 8, newSize, 8);
  set(b, g.sectionSizeField, newSize + 8, 8); // section_64.size; segment unchanged.
  const auto check = locateGraph(b);
  require(check.count == rows.size() && check.size == newSize,
          "graph metadata readback");
  write(argv[3], b);
  std::cout << "{\"module_count\":" << rows.size()
            << ",\"javascript_count\":" << javascript
            << ",\"native_loader_records\":" << native
            << ",\"entry_index\":" << (selected - rows.begin())
            << ",\"startup_count\":" << startup
            << ",\"flags\":" << flags
            << ",\"jit_scale\":" << jitScale
            << ",\"bootstrap_record_removed\":true"
            << ",\"all_retained_body_hashes_match\":true"
            << ",\"native_addons_executed\":false}\n";
  return 0;
} catch (const std::exception &e) {
  std::cerr << e.what() << '\n';
  return 1;
}
