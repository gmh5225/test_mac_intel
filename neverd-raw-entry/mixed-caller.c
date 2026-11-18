#define NEVERD_TEST_MIXED_DATA 1

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
typedef unsigned long (*operation)(unsigned long, unsigned long);

int main(int argc, char **argv) {
  if (argc != 2)
    return 1;
  void *image = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!image) {
    fputs(dlerror(), stderr);
    return 2;
  }
#ifdef NEVERD_TEST_SPLIT_DATA
  const unsigned char *marker = dlsym(image, "split_marker");
  if (!marker || marker[0] != 0x31 || marker[1] != 0x72 || marker[2] != 0xa5)
    return 5;
#endif
  operation sum = (operation)dlsym(image, "leaf_sum");
  operation difference = (operation)dlsym(image, "leaf_difference");
  if (!sum || !difference)
    return 3;
  const unsigned long values[] = {0, 1, 17, UINT64_MAX, UINT64_C(1) << 63};
  for (unsigned i = 0; i != sizeof(values) / sizeof(*values); ++i)
    for (unsigned j = 0; j != sizeof(values) / sizeof(*values); ++j)
#if defined(NEVERD_TEST_TAIL_SUM)
      if (sum(values[i], values[j]) != values[i] + values[j] ||
          difference(values[i], values[j]) != values[i] + values[j])
#elif defined(NEVERD_TEST_MIXED_DATA)
      if (sum(values[i], values[j]) != values[i] + values[j] + UINT32_C(0xd503237f) ||
          difference(values[i], values[j]) != values[i] - values[j])
#elif defined(NEVERD_TEST_ZERO_RESULTS)
      if (sum(values[i], values[j]) != 0 || difference(values[i], values[j]) != 0)
#else
      if (sum(values[i], values[j]) != values[i] + values[j] ||
          difference(values[i], values[j]) != values[i] - values[j])
#endif
        return 4;
  return dlclose(image) != 0;
}
