// Private adapters for independently compiled, pinned Bun native containers.
// Shared serialized-graph interpretation remains in the source-graph adapter.
struct NativeGraph {
  uint64_t base, size, sectionSizeField;
};
NativeGraph locateNativeGraph(const Bytes &b) {
  if (number(b, 0, 4) == 0xfeedfacf) {
    require(number(b, 4, 4) == 0x100000c || number(b, 4, 4) == 0x1000007, "MachO arm64 or x64 required");
    uint64_t pos = 32;
    unsigned found = 0;
    NativeGraph graph{};
    const auto count = number(b, 16, 4);
    require(count <= 4096, "MachO commands budget");
    for (uint64_t i = 0; i < count; ++i) {
      const auto command = number(b, pos, 4), length = number(b, pos + 4, 4);
      require(length >= 8 && length <= 1024 * 1024, "MachO command");
      if (command == 25 && text(b, pos + 8, 16) ==
              std::string("__BUN\0\0\0\0\0\0\0\0\0\0\0", 16)) {
        require(++found == 1 && length == 152 && number(b, pos + 64, 4) == 1,
                "Bun MachO segment");
        const auto start = number(b, pos + 40, 8);
        const auto size = number(b, start, 8);
        require(size >= 48 && start + 8 <= b.size() && size <= b.size() - start - 8 &&
                    number(b, pos + 112, 8) == size + 8, "MachO graph range");
        graph = {start + 8, size, pos + 112};
      }
      pos += length;
    }
    require(found == 1, "MachO graph missing");
    return graph;
  }
  require(text(b, 0, 4) == std::string("\177ELF", 4) &&
              number(b, 4, 1) == 2 && number(b, 5, 1) == 1 &&
              number(b, 6, 1) == 1 && (number(b, 18, 2) == 62 || number(b, 18, 2) == 183) &&
              number(b, 52, 2) == 64 && number(b, 54, 2) == 56 &&
              number(b, 58, 2) == 64, "qualified ELF64 little-endian Linux architecture required");
  const auto sh = number(b, 40, 8), sn = number(b, 60, 2), si = number(b, 62, 2);
  const auto ph = number(b, 32, 8), pn = number(b, 56, 2);
  require(sn && sn <= 4096 && si && si < sn && pn && pn <= 1024,
          "ELF table budget");
  text(b, sh, sn * 64); text(b, ph, pn * 56);
  require(number(b, sh + si * 64 + 4, 4) == 3, "ELF name table type");
  const auto names = text(b, number(b, sh + si * 64 + 24, 8),
                         number(b, sh + si * 64 + 32, 8));
  require(!names.empty() && names.size() < 1024 * 1024 && names.front() == 0 &&
              names.back() == 0, "ELF name table");
  unsigned found = 0;
  NativeGraph graph{};
  for (uint64_t i = 0; i < sn; ++i) {
    const auto at = sh + i * 64, name = number(b, at, 4);
    require(name < names.size(), "ELF section name offset");
    if (names.substr(name, 5) != std::string(".bun\0", 5)) continue;
    require(++found == 1 && number(b, at + 4, 4) == 1 && number(b, at + 8, 8) == 3,
            "Bun ELF section type");
    const auto start = number(b, at + 24, 8), length = number(b, at + 32, 8);
    const auto address = number(b, at + 16, 8);
    require(length >= 56 && start <= b.size() && length <= b.size() - start &&
                address % 4096 == 0, "Bun ELF section range");
    const auto size = number(b, start, 8);
    require(size == length - 8, "Bun ELF length prefix");
    unsigned owners = 0;
    for (uint64_t j = 0; j < pn; ++j) {
      const auto p = ph + j * 56;
      if (number(b, p, 4) != 1) continue;
      const auto file = number(b, p + 8, 8), fileSize = number(b, p + 32, 8);
      const auto virt = number(b, p + 16, 8), virtSize = number(b, p + 40, 8);
      require(file <= b.size() && fileSize <= b.size() - file, "ELF load file range");
      if (start < file || start - file >= fileSize) continue;
      require(++owners == 1 && number(b, p + 4, 4) == 6 && fileSize == virtSize &&
                  length <= fileSize - (start - file) && address >= virt &&
                  start - file == address - virt, "Bun ELF load mapping");
    }
    require(owners == 1, "Bun ELF load owner");
    graph = {start + 8, size, at + 32};
  }
  require(found == 1, "ELF graph missing");
  return graph;
}
