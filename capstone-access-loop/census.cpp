#include <capstone/capstone.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
#include "evex_rows.inc"

struct Stats {
  uint64_t valid = 0, invalid = 0, vectors = 0, functions = 0;
  std::map<std::string, uint64_t> counts;
  void add(const Stats &s) {
    valid += s.valid; invalid += s.invalid; vectors += s.vectors;
    functions += s.functions;
    for (const auto &p : s.counts) counts[p.first] += p.second;
  }
  void print() const {
    std::printf("{\"decoded\":%llu,\"invalid_bytes\":%llu,\"vectors\":%llu,\"functions\":%llu,\"counts\":{",
      (unsigned long long)valid, (unsigned long long)invalid,
      (unsigned long long)vectors, (unsigned long long)functions);
    bool comma = false;
    for (const auto &p : counts) {
      std::printf("%s\"%s\":%llu", comma ? "," : "", p.first.c_str(),
                  (unsigned long long)p.second); comma = true;
    }
    std::printf("}}");
  }
};

int main(int argc, char **argv) {
  try {
    if (argc != 4) return 1;
    unsigned bits = std::stoul(argv[1]);
    csh full = 0, raw = 0, canonical = 0;
    cs_mode mode = bits == 64 ? CS_MODE_64 : CS_MODE_32;
    if (cs_open(CS_ARCH_X86, mode, &full) || cs_open(CS_ARCH_X86, mode, &raw) ||
        cs_open(CS_ARCH_X86, mode, &canonical) ||
        cs_option(canonical, CS_OPT_DETAIL, CS_OPT_ON) ||
        cs_option(canonical, CS_OPT_TEXT, CS_OPT_OFF) ||
        cs_option(full, CS_OPT_DETAIL, CS_OPT_ON) ||
        cs_option(raw, CS_OPT_TEXT, CS_OPT_OFF)) return 2;
    cs_insn *insn = cs_malloc(full), *scan = cs_malloc(raw), *reference = cs_malloc(canonical);
    if (!insn || !scan || !reference) return 2;
    std::ifstream input(argv[2], std::ios::binary), spans(argv[3]);
    if (!input || !spans) return 3;
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input), {}};
    Stats all, simd;
    size_t start, left; uint64_t address;
    while (spans >> start >> left >> address) {
      if (start > bytes.size() || left > bytes.size() - start) return 3;
      const uint8_t *cursor = bytes.data() + start;
      Stats local; local.functions = 1;
      while (left) {
        const uint8_t *begin = cursor, *raw_cursor = cursor, *reference_cursor = cursor;
        size_t before = left, raw_left = left, reference_left = left; uint64_t raw_ip = address, reference_ip = address;
        bool ok = cs_disasm_iter(full, &cursor, &left, &address, insn);
        bool raw_ok = cs_disasm_iter(raw, &raw_cursor, &raw_left, &raw_ip, scan);
        bool reference_ok = cs_disasm_iter(canonical, &reference_cursor, &reference_left, &reference_ip, reference);
        if (ok != raw_ok || cursor != raw_cursor || left != raw_left || address != raw_ip ||
            reference_ok != raw_ok || reference_cursor != raw_cursor || reference_left != raw_left || reference_ip != raw_ip ||
            (ok && (reference->id != scan->id || reference->size != scan->size || insn->size != scan->size))) {
          std::fprintf(stderr,"mismatch bits=%u offset=%zu ip=%llx full_ok=%u raw_ok=%u full_id=%u raw_id=%u full_size=%u raw_size=%u full_left=%zu raw_left=%zu bytes=",
            bits,size_t(begin-bytes.data()),(unsigned long long)(address-(before-left)),ok,raw_ok,insn->id,scan->id,insn->size,scan->size,left,raw_left);
          for(size_t i=0;i<before && i<15;++i)std::fprintf(stderr,"%02x",begin[i]);
          std::fprintf(stderr," canonical_id=%u canonical_size=%u full_text=%s %s\n",reference->id,reference->size,insn->mnemonic,insn->op_str);
          throw std::runtime_error("raw/full decode mismatch");
        }
        if (!ok) { ++local.invalid; ++cursor; --left; ++address; continue; }
        ++local.valid;
        if(insn->id!=scan->id)++local.counts["printed-predicate-id-adjustments"];
        const cs_x86 &detail = insn->detail->x86;
        for (unsigned i = 0; i < detail.op_count; ++i) {
          if (detail.operands[i].type != X86_OP_REG) continue;
          const char *n = cs_reg_name(full, detail.operands[i].reg);
          if (n && (!std::strncmp(n,"xmm",3) || !std::strncmp(n,"ymm",3) || !std::strncmp(n,"zmm",3))) {
            ++local.vectors; break;
          }
        }
        const char *name = cs_insn_name(full, insn->id);
        if (!name) throw std::runtime_error("instruction name");
        if (begin[0] == 0xc5 && insn->id != X86_INS_LDS) ++local.counts["bare_c5"];
        if (begin[0] == 0xc4 && insn->id != X86_INS_LES) {
          ++local.counts["bare_c4"];
          bool memory = false;
          for (unsigned i = 0; i < detail.op_count; ++i) memory |= detail.operands[i].type == X86_OP_MEM;
          ++local.counts[std::string("c4/") + (memory ? "memory/" : "register/") + name];
        }
        if (begin[0] != 0x62 || insn->id == X86_INS_BOUND) continue;
        ++local.counts["bare_62"];
        if (before < 6) throw std::runtime_error("short EVEX");
        const bool memory = begin[5] < 0xc0;
        const bool pp = (begin[2] & 7) != 5;
        const bool mask = (begin[3] & 0x87) != 0;
        const bool broadcast = (begin[3] & 0x10) != 0;
        const bool bad_ll = (begin[3] & 0x60) == 0x60;
        const unsigned key = ((begin[1] & 15) << 8) | begin[4];
        const VectorOutputRow *row = nullptr;
        if (!pp && !mask && !broadcast && !bad_ll)
          row = evexOutputRow(key, begin[2] >> 7, begin[3] >> 5);
        const bool extract_source = (key & ~0x22u) == 0x319 &&
          ((begin[2] & 0x78) != 0x78 || !(begin[3] & 8));
        bool admitted = bits == 64 && !memory && row && !extract_source &&
          (!row->immediate || before >= 7);
        if (admitted && (row->id != insn->id || row->id != reference->id || insn->size != 6 + row->immediate))
          throw std::runtime_error("existing EVEX row disagrees with canonical decoder");
        ++local.counts[admitted ? "evex/admitted" : "evex/missed"];
        std::string flags = std::string(memory ? "mem" : "reg") +
          (pp ? "+pp" : "") + (mask ? "+mask" : "") +
          (broadcast ? "+b" : "") + (bad_ll ? "+ll3" : "");
        ++local.counts["evex/shape/" + flags];
        if (!admitted) ++local.counts["evex/missed/" + flags + "/" + name];
        if (!memory && !pp && !mask && !broadcast && !bad_ll && !row)
          ++local.counts[std::string("evex/missing-row/") + name];
      }
      all.add(local);
      if (local.vectors >= 8 && local.vectors >= .15 * local.valid) simd.add(local);
    }
    std::printf("{\"all-functions\":"); all.print();
    std::printf(",\"simd-functions\":"); simd.print(); std::puts("}");
    cs_free(insn, 1); cs_free(scan, 1); cs_free(reference, 1); cs_close(&full); cs_close(&raw); cs_close(&canonical);
  } catch (const std::exception &e) {
    std::fprintf(stderr,"%s\n",e.what()); return 4;
  }
}
