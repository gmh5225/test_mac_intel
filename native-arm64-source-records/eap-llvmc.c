#include <stdbool.h>
#include <stdint.h>


typedef struct HWND__ HWND__;
typedef struct _EAP_ERROR _EAP_ERROR;
typedef struct _EAP_METHOD_TYPE _EAP_METHOD_TYPE;

// 5 types, from the program's local types.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__cplusplus) && !defined(static_assert)
#define static_assert _Static_assert
#endif

#ifndef NEVERD_TYPE_BYTE
#define NEVERD_TYPE_BYTE
typedef uint8_t BYTE;
#endif

#ifndef NEVERD_TYPE_DWORD
#define NEVERD_TYPE_DWORD
typedef uint32_t DWORD;
#endif

#ifndef NEVERD_TYPE__EAP_TYPE
#define NEVERD_TYPE__EAP_TYPE
// _EAP_TYPE: 0xC (12) bytes
struct _EAP_TYPE
{
    BYTE type;                                                  // 0x0
    // 0x1: 3 bytes of padding
    DWORD dwVendorId;                                           // 0x4
    DWORD dwVendorType;                                         // 0x8
};
static_assert(sizeof(struct _EAP_TYPE) == 0xC, "_EAP_TYPE");
static_assert(offsetof(struct _EAP_TYPE, type) == 0x0, "_EAP_TYPE.type");
static_assert(offsetof(struct _EAP_TYPE, dwVendorId) == 0x4, "_EAP_TYPE.dwVendorId");
static_assert(offsetof(struct _EAP_TYPE, dwVendorType) == 0x8, "_EAP_TYPE.dwVendorType");
#endif

#ifndef NEVERD_TYPE_EAP_TYPE
#define NEVERD_TYPE_EAP_TYPE
typedef struct _EAP_TYPE EAP_TYPE;
#endif

#ifndef NEVERD_TYPE__EAP_METHOD_TYPE
#define NEVERD_TYPE__EAP_METHOD_TYPE
// _EAP_METHOD_TYPE: 0x10 (16) bytes
struct _EAP_METHOD_TYPE
{
    EAP_TYPE eapType;                                           // 0x00
    DWORD dwAuthorId;                                           // 0x0C
};
static_assert(sizeof(struct _EAP_METHOD_TYPE) == 0x10, "_EAP_METHOD_TYPE");
static_assert(offsetof(struct _EAP_METHOD_TYPE, eapType) == 0x0, "_EAP_METHOD_TYPE.eapType");
static_assert(offsetof(struct _EAP_METHOD_TYPE, dwAuthorId) == 0xC, "_EAP_METHOD_TYPE.dwAuthorId");
#endif


__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) EapHostPeerInvokeConfigUI(HWND__* hwndParent, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) dwFlags, struct _EAP_METHOD_TYPE eapMethodType, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) dwSizeOfConfigIn, uint8_t* pConfigIn, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0))* pdwSizeOfConfigOut, uint8_t** ppConfigOut, _EAP_ERROR** ppEapError);
uint64_t InspectEapHostPeerInvokeConfigUI(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t arg8) {
    uint64_t call0;

    call0 = ((uint64_t)(uint32_t)(EapHostPeerInvokeConfigUI((HWND__*)(uintptr_t)(arg0), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)))(uintptr_t)(arg1), ({ struct _EAP_METHOD_TYPE __neverd_record; uint64_t __neverd_piece0 = (uint64_t)(uintptr_t)(arg2); __builtin_memcpy((unsigned char *)&__neverd_record + 0, &__neverd_piece0, 8); uint64_t __neverd_piece1 = (uint64_t)(uintptr_t)(arg3); __builtin_memcpy((unsigned char *)&__neverd_record + 8, &__neverd_piece1, 8); __neverd_record; }), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)))(uintptr_t)(arg4), (uint8_t*)(uintptr_t)(arg5), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0))*)(uintptr_t)(arg6), (uint8_t**)(uintptr_t)(arg7), (_EAP_ERROR**)(uintptr_t)(arg8))));
    return call0;
}

