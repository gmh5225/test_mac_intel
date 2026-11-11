#define main timed_entry
#include "single-msvc.cpp"
#undef main
#include <bcrypt.h>
#include <cstring>

extern "C" unsigned long long alias_direct_count, alias_heap_count;

int main(int argc, char **argv) {
  if (argc != 4) return 2;
  API api;
  const unsigned selector = std::stoul(argv[1]), mode = std::stoul(argv[2]);
  Session s(api, selector, mode);
  std::ifstream f(argv[3], std::ios::binary);
  std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)), {});
  if (bytes.empty()) return 2;
  BCRYPT_ALG_HANDLE provider;
  BCRYPT_HASH_HANDLE hash;
  if (BCryptOpenAlgorithmProvider(&provider, BCRYPT_SHA256_ALGORITHM, nullptr, 0) ||
      BCryptCreateHash(provider, &hash, nullptr, 0, nullptr, 0, 0)) return 3;
  auto append = [&](const void *p, size_t n) {
    if (BCryptHashData(hash, (PUCHAR)p, (ULONG)n, 0)) throw std::runtime_error("hash update");
  };
  uint64_t ip = 0x100000, n = 0;
  size_t remaining = bytes.size();
  const uint8_t *cursor = bytes.data();
  while (remaining) {
    auto *d = s.insn->detail;
    memset(s.insn, 0x5a, sizeof(*s.insn));
    s.insn->detail = d;
    if (d) memset(d, 0xa5, sizeof(*d));
    bool ok = cs_disasm_iter(s.handle, &cursor, &remaining, &ip, s.insn);
    auto err = cs_errno(s.handle);
    auto pos = cursor - bytes.data();
    append(&ok, sizeof(ok)); append(&err, sizeof(err)); append(&ip, sizeof(ip));
    append(&pos, sizeof(pos)); append(&remaining, sizeof(remaining));
    s.insn->detail = nullptr;
    append(s.insn, sizeof(*s.insn));
    s.insn->detail = d;
    if (d) append(d, sizeof(*d));
    if (ok && d) {
      cs_regs rd{}, wr{};
      uint8_t nr=0,nw=0;
      auto access=cs_regs_access(s.handle,s.insn,rd,&nr,wr,&nw);
      append(&access,sizeof(access)); append(&nr,1); append(rd,sizeof(rd));
      append(&nw,1); append(wr,sizeof(wr));
    }
    if (!ok) { ++cursor; --remaining; ++ip; }
    ++n;
  }
  unsigned char digest[32];
  if (BCryptFinishHash(hash,digest,sizeof(digest),0)) return 3;
  BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(provider,0);
  printf("{\"records\":%llu,\"direct\":%llu,\"heap\":%llu,\"sha256\":\"",n,alias_direct_count,alias_heap_count);
  for (auto x:digest) printf("%02x", x);
  puts("\"}");
}
