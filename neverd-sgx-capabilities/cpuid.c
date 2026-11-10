/* NeverD SGX runner discovery: CPUID only, no enclave or privileged opcode. */
#include <cpuid.h>
#include <stdio.h>

#if !defined(__x86_64__)
#error This probe requires an x86-64 runner
#endif

int main(void) {
  const unsigned leaves[][2] = {{0, 0}, {1, 0}, {7, 0}, {0x12, 0},
                                {0x12, 1}, {0x12, 2}, {0x80000000, 0},
                                {0x80000002, 0}, {0x80000003, 0},
                                {0x80000004, 0}};
  puts("[");
  for (unsigned i = 0; i != sizeof(leaves) / sizeof(leaves[0]); ++i) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    const unsigned leaf = leaves[i][0], subleaf = leaves[i][1];
    const int available = __get_cpuid_count(leaf, subleaf, &a, &b, &c, &d);
    printf("%s{\"leaf\":%u,\"subleaf\":%u,\"available\":%s,"
           "\"registers\":[%u,%u,%u,%u]}\n",
           i ? "," : "", leaf, subleaf, available ? "true" : "false",
           a, b, c, d);
  }
  puts("]");
  return 0;
}
