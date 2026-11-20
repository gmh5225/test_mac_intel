
#include <dlfcn.h>
#include <stdint.h>

typedef uint64_t (*dispatch)(uint64_t, uint64_t);
int main(int argc, char **argv) {
  if (argc != 2)
    return 1;
  void *image = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!image)
    return 2;
  const char *names[] = {"leaf_sum", "leaf_difference", "leaf_wide"};
  const uint64_t cases[] = {43, 11, 29, 11};
  const uint64_t inputs[] = {0, 1, 2, 3, 4, UINT32_MAX, UINT64_MAX,
                             (UINT64_C(1) << 32) + 2};
  const uint64_t bases[] = {0, 17, UINT64_MAX};
  for (unsigned f = 0; f < sizeof(names)/sizeof(*names); ++f) {
    dispatch call = (dispatch)dlsym(image, names[f]);
    if (!call)
      return 3;
    for (unsigned i = 0; i < sizeof(inputs)/sizeof(*inputs); ++i) {
      const uint32_t index = (uint32_t)inputs[i];
      for (unsigned b = 0; b < sizeof(bases)/sizeof(*bases); ++b) {
        uint64_t expected = index < sizeof(cases)/sizeof(*cases)
                                ? bases[b] + cases[index] : bases[b] - 5;
        if (call(inputs[i], bases[b]) != expected)
          return 4;
      }
    }
  }
  return dlclose(image) != 0;
}
