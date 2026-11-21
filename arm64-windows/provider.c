// NeverD Decompiler. Copyright (C) 2026 NeverD contributors.
// SPDX-License-Identifier: AGPL-3.0-only
// Observable ABI models, not implementations of Windows kernel APIs.
#include <stddef.h>
#include <stdint.h>
#define API __declspec(dllexport)
static uint64_t trace[64];
static unsigned mode;
static void record(uint64_t v) {
  unsigned i = (unsigned)trace[0] + 1;
  trace[i] = v;
  trace[0] = i;
}
API void ModelReset(unsigned value) {
  mode = value;
  for (unsigned i = 0; i < 64; ++i)
    trace[i] = 0;
}
API void ModelSnapshot(uint64_t *out) {
  for (unsigned i = 0; i < 64; ++i)
    out[i] = trace[i];
}
API uint32_t D3DCompile2(const void *data, size_t size, const char *name,
                         const void *defines, void *include, const char *entry,
                         const char *target, uint32_t flags1, uint32_t flags2,
                         uint32_t secondary_flags, const void *secondary,
                         size_t secondary_size, void **code, void **errors) {
  record(14);
  record((uintptr_t)data);
  record(size);
  record((uintptr_t)name);
  record((uintptr_t)defines);
  record((uintptr_t)include);
  record((uintptr_t)entry);
  record((uintptr_t)target);
  record(flags1);
  record(flags2);
  record(secondary_flags);
  record((uintptr_t)secondary);
  record(secondary_size);
  record((uintptr_t)code);
  record((uintptr_t)errors);
  return 0x80223344u;
}
API uint32_t SdPortGetPciConfigSpace(void *miniport, uint8_t offset,
                                     uint8_t *out, uint32_t length) {
  record(11);
  record((uintptr_t)miniport);
  record(offset);
  record((uintptr_t)out);
  record(length);
  for (uint32_t i = 0; i < length; ++i)
    out[i] = (uint8_t)(offset + i);
  return length;
}
typedef int32_t (*StartDevice)(void *, void *, void *);
API int32_t PcAddAdapterDevice(void *driver, void *device, StartDevice start,
                               uint32_t maximum, uint32_t extension) {
  record(12);
  record((uintptr_t)driver);
  record((uintptr_t)device);
  record((uintptr_t)start);
  record(maximum);
  record(extension);
  return (int32_t)((uint32_t)start(device, 0, 0) ^ maximum ^ extension);
}
API void StreamClassQueryMasterClockSync(void *handle, void *context) {
  record(13);
  record((uintptr_t)handle);
  record((uintptr_t)context);
  ((uint64_t *)context)[0] = 0x1122334455667788ull;
  ((uint64_t *)context)[1] = 0x8877665544332211ull;
}
API int32_t NdisOpenConfigurationEx(void *config, void **handle) {
  record(1);
  record((uintptr_t)config);
  record(handle != 0);
  *handle = (void *)(uintptr_t)0x123450;
  return mode == 1 ? (int32_t)0xc0000001u : 0;
}
API void NdisReadConfiguration(int32_t *status, void **parameter, void *handle,
                               void *keyword, int kind) {
  record(2);
  record(status != 0);
  record(parameter != 0);
  record((uintptr_t)handle);
  record((uintptr_t)keyword);
  record((uint32_t)kind);
  *status = mode == 2 ? (int32_t)0xc000000du : 0;
  *parameter = (void *)(uintptr_t)0x678900;
}
API void NdisCloseConfiguration(void *handle) {
  record(3);
  record((uintptr_t)handle);
}

API int32_t RxRegisterMinirdr(void **device, void *driver, void *dispatch,
                              uint32_t controls, void *name, uint32_t extension,
                              uint32_t type, uint32_t characteristics) {
  record(41);
  record((uintptr_t)device);
  record((uintptr_t)driver);
  record((uintptr_t)dispatch);
  record(controls);
  record((uintptr_t)name);
  record(extension);
  record(type);
  record(characteristics);
  *device = (void *)((uintptr_t)driver ^ UINT64_C(0x5678000) ^ controls);
  return (int32_t)(0xc0001200u | mode);
}
API int32_t RxStartMinirdr(void *context, uint8_t *post) {
  record(42);
  record((uintptr_t)context);
  record((uintptr_t)post);
  *post = (uint8_t)(mode ^ 0xa5);
  return (int32_t)(0x80000300u | mode);
}
API void RxpUnregisterMinirdr(void *device) {
  record(43);
  record((uintptr_t)device);
}
API void *RxCreateRxContext(void *irp, void *device, uint32_t flags) {
  record(44);
  record((uintptr_t)irp);
  record((uintptr_t)device);
  record(flags);
  return (void *)(UINT64_C(0x100000000) | (flags ^ UINT64_C(0x11223344)));
}
API int32_t RxInitializeDispatcher(void) {
  record(45);
  return (int32_t)(0xc0004500u | mode);
}
API int32_t RxInitializeRxTimer(void) {
  record(46);
  return (int32_t)(0xc0004600u | mode);
}
API int32_t RxTearDownDispatcher(void) {
  record(47);
  return (int32_t)(0xc0004700u | mode);
}
