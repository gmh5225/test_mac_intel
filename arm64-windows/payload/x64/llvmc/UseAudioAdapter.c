#include <stdint.h>

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */


typedef struct AudioPort__DEVICE_OBJECT AudioPort__DEVICE_OBJECT;
typedef struct AudioPort__DRIVER_OBJECT AudioPort__DRIVER_OBJECT;
typedef struct AudioPort__IRP AudioPort__IRP;
typedef struct IResourceList IResourceList;

// 29 types, from the program's local types.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef DECLSPEC_ALIGN
#if defined(_MSC_VER)
#define DECLSPEC_ALIGN(x) __declspec(align(x))
#else
#define DECLSPEC_ALIGN(x) __attribute__((aligned(x)))
#endif
#endif

#if !defined(__cplusplus) && !defined(static_assert)
#define static_assert _Static_assert
#endif

struct IResourceListVtbl;
struct _MDL;
struct AudioPort__KEVENT;
struct AudioPort__DEVICE_OBJECT;
struct _ETHREAD;
struct AudioPort__FILE_OBJECT;
struct _KTHREAD;
struct _IORING_OBJECT;
struct AudioPort__IO_STACK_LOCATION;

#ifndef NEVERD_TYPE__LARGE_INTEGER
#define NEVERD_TYPE__LARGE_INTEGER
// _LARGE_INTEGER: 0x8 (8) bytes
union _LARGE_INTEGER
{
    struct                                                      // 0x0
    {
        uint32_t LowPart;                                       // 0x0
        int32_t HighPart;                                       // 0x4
    };
    struct
    {
        uint32_t LowPart;                                       // 0x0
        int32_t HighPart;                                       // 0x4
    } u;                                                        // 0x0
    int64_t QuadPart;                                           // 0x0
};
static_assert(sizeof(union _LARGE_INTEGER) == 0x8, "_LARGE_INTEGER");
static_assert(offsetof(union _LARGE_INTEGER, LowPart) == 0x0, "_LARGE_INTEGER.LowPart");
static_assert(offsetof(union _LARGE_INTEGER, HighPart) == 0x4, "_LARGE_INTEGER.HighPart");
static_assert(offsetof(union _LARGE_INTEGER, u) == 0x0, "_LARGE_INTEGER.u");
static_assert(offsetof(union _LARGE_INTEGER, QuadPart) == 0x0, "_LARGE_INTEGER.QuadPart");
#endif

#ifndef NEVERD_TYPE__LIST_ENTRY
#define NEVERD_TYPE__LIST_ENTRY
// _LIST_ENTRY: 0x10 (16) bytes
struct _LIST_ENTRY
{
    struct _LIST_ENTRY *Flink;                                  // 0x00
    struct _LIST_ENTRY *Blink;                                  // 0x08
};
static_assert(sizeof(struct _LIST_ENTRY) == 0x10, "_LIST_ENTRY");
static_assert(offsetof(struct _LIST_ENTRY, Flink) == 0x0, "_LIST_ENTRY.Flink");
static_assert(offsetof(struct _LIST_ENTRY, Blink) == 0x8, "_LIST_ENTRY.Blink");
#endif

#ifndef NEVERD_TYPE_NTSTATUS
#define NEVERD_TYPE_NTSTATUS
typedef int32_t NTSTATUS;
#endif

#ifndef NEVERD_TYPE_PVOID
#define NEVERD_TYPE_PVOID
typedef void *PVOID;
#endif

#ifndef NEVERD_TYPE_ULONG_PTR
#define NEVERD_TYPE_ULONG_PTR
typedef uint64_t ULONG_PTR;
#endif

#ifndef NEVERD_TYPE__IO_STATUS_BLOCK
#define NEVERD_TYPE__IO_STATUS_BLOCK
// _IO_STATUS_BLOCK: 0x10 (16) bytes
struct _IO_STATUS_BLOCK
{
    union                                                       // 0x00
    {
        NTSTATUS Status;                                        // 0x00
        PVOID Pointer;                                          // 0x00
    };
    ULONG_PTR Information;                                      // 0x08
};
static_assert(sizeof(struct _IO_STATUS_BLOCK) == 0x10, "_IO_STATUS_BLOCK");
static_assert(offsetof(struct _IO_STATUS_BLOCK, Status) == 0x0, "_IO_STATUS_BLOCK.Status");
static_assert(offsetof(struct _IO_STATUS_BLOCK, Pointer) == 0x0, "_IO_STATUS_BLOCK.Pointer");
static_assert(offsetof(struct _IO_STATUS_BLOCK, Information) == 0x8, "_IO_STATUS_BLOCK.Information");
#endif

#ifndef NEVERD_TYPE_IResourceList
#define NEVERD_TYPE_IResourceList
// IResourceList: 0x8 (8) bytes
struct IResourceList
{
    struct IResourceListVtbl *lpVtbl;                           // 0x0
};
static_assert(sizeof(struct IResourceList) == 0x8, "IResourceList");
static_assert(offsetof(struct IResourceList, lpVtbl) == 0x0, "IResourceList.lpVtbl");
#endif

#ifndef NEVERD_TYPE_CSHORT
#define NEVERD_TYPE_CSHORT
typedef int16_t CSHORT;
#endif

#ifndef NEVERD_TYPE_PMDL
#define NEVERD_TYPE_PMDL
typedef struct _MDL *PMDL;
#endif

#ifndef NEVERD_TYPE_LIST_ENTRY
#define NEVERD_TYPE_LIST_ENTRY
typedef struct _LIST_ENTRY LIST_ENTRY;
#endif

#ifndef NEVERD_TYPE_IO_STATUS_BLOCK
#define NEVERD_TYPE_IO_STATUS_BLOCK
typedef struct _IO_STATUS_BLOCK IO_STATUS_BLOCK;
#endif

#ifndef NEVERD_TYPE_CCHAR
#define NEVERD_TYPE_CCHAR
typedef char CCHAR;
#endif

#ifndef NEVERD_TYPE_KPROCESSOR_MODE
#define NEVERD_TYPE_KPROCESSOR_MODE
typedef CCHAR KPROCESSOR_MODE;
#endif

#ifndef NEVERD_TYPE_AudioPort_BOOLEAN
#define NEVERD_TYPE_AudioPort_BOOLEAN
typedef uint8_t AudioPort_BOOLEAN;
#endif

#ifndef NEVERD_TYPE_KIRQL
#define NEVERD_TYPE_KIRQL
typedef uint8_t KIRQL;
#endif

#ifndef NEVERD_TYPE_PIO_STATUS_BLOCK
#define NEVERD_TYPE_PIO_STATUS_BLOCK
typedef struct _IO_STATUS_BLOCK *PIO_STATUS_BLOCK;
#endif

#ifndef NEVERD_TYPE_AudioPort_PKEVENT
#define NEVERD_TYPE_AudioPort_PKEVENT
typedef struct AudioPort__KEVENT *AudioPort_PKEVENT;
#endif

#ifndef NEVERD_TYPE_PIO_APC_ROUTINE
#define NEVERD_TYPE_PIO_APC_ROUTINE
typedef void (*PIO_APC_ROUTINE)(PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, uint32_t Reserved);
#endif

#ifndef NEVERD_TYPE_LARGE_INTEGER
#define NEVERD_TYPE_LARGE_INTEGER
typedef union _LARGE_INTEGER LARGE_INTEGER;
#endif

#ifndef NEVERD_TYPE_AudioPort_DRIVER_CANCEL
#define NEVERD_TYPE_AudioPort_DRIVER_CANCEL
typedef void AudioPort_DRIVER_CANCEL(struct AudioPort__DEVICE_OBJECT *DeviceObject, struct AudioPort__IRP *Irp);
#endif

#ifndef NEVERD_TYPE_AudioPort_PDRIVER_CANCEL
#define NEVERD_TYPE_AudioPort_PDRIVER_CANCEL
typedef AudioPort_DRIVER_CANCEL *AudioPort_PDRIVER_CANCEL;
#endif

#ifndef NEVERD_TYPE_AudioPort_KDEVICE_QUEUE_ENTRY
#define NEVERD_TYPE_AudioPort_KDEVICE_QUEUE_ENTRY
typedef struct AudioPort__KDEVICE_QUEUE_ENTRY AudioPort_KDEVICE_QUEUE_ENTRY;
#endif

#ifndef NEVERD_TYPE_AudioPort_PETHREAD
#define NEVERD_TYPE_AudioPort_PETHREAD
typedef struct _ETHREAD *AudioPort_PETHREAD;
#endif

#ifndef NEVERD_TYPE_PCHAR
#define NEVERD_TYPE_PCHAR
typedef char *PCHAR;
#endif

#ifndef NEVERD_TYPE_AudioPort_PFILE_OBJECT
#define NEVERD_TYPE_AudioPort_PFILE_OBJECT
typedef struct AudioPort__FILE_OBJECT *AudioPort_PFILE_OBJECT;
#endif

#ifndef NEVERD_TYPE_AudioPort_KAPC
#define NEVERD_TYPE_AudioPort_KAPC
typedef struct AudioPort__KAPC AudioPort_KAPC;
#endif

#ifndef NEVERD_TYPE_AudioPort__KDEVICE_QUEUE_ENTRY
#define NEVERD_TYPE_AudioPort__KDEVICE_QUEUE_ENTRY
// AudioPort__KDEVICE_QUEUE_ENTRY: 0x18 (24) bytes
struct AudioPort__KDEVICE_QUEUE_ENTRY
{
    LIST_ENTRY DeviceListEntry;                                 // 0x00
    uint32_t SortKey;                                           // 0x10
    AudioPort_BOOLEAN Inserted;                                 // 0x14
    // 0x15: 3 bytes of padding
};
static_assert(sizeof(struct AudioPort__KDEVICE_QUEUE_ENTRY) == 0x18, "AudioPort__KDEVICE_QUEUE_ENTRY");
static_assert(offsetof(struct AudioPort__KDEVICE_QUEUE_ENTRY, DeviceListEntry) == 0x0, "AudioPort__KDEVICE_QUEUE_ENTRY.DeviceListEntry");
static_assert(offsetof(struct AudioPort__KDEVICE_QUEUE_ENTRY, SortKey) == 0x10, "AudioPort__KDEVICE_QUEUE_ENTRY.SortKey");
static_assert(offsetof(struct AudioPort__KDEVICE_QUEUE_ENTRY, Inserted) == 0x14, "AudioPort__KDEVICE_QUEUE_ENTRY.Inserted");
#endif

#ifndef NEVERD_TYPE_AudioPort__KAPC
#define NEVERD_TYPE_AudioPort__KAPC
// AudioPort__KAPC: 0x58 (88) bytes
struct AudioPort__KAPC
{
    uint8_t Type;                                               // 0x00
    uint8_t AllFlags;                                           // 0x01
    uint8_t Size;                                               // 0x02
    uint8_t SpareByte1;                                         // 0x03
    uint32_t SpareLong0;                                        // 0x04
    struct _KTHREAD *Thread;                                    // 0x08
    LIST_ENTRY ApcListEntry;                                    // 0x10
    PVOID Reserved[3];                                          // 0x20
    PVOID NormalContext;                                        // 0x38
    PVOID SystemArgument1;                                      // 0x40
    PVOID SystemArgument2;                                      // 0x48
    CCHAR ApcStateIndex;                                        // 0x50
    KPROCESSOR_MODE ApcMode;                                    // 0x51
    AudioPort_BOOLEAN Inserted;                                 // 0x52
    // 0x53: 5 bytes of padding
};
static_assert(sizeof(struct AudioPort__KAPC) == 0x58, "AudioPort__KAPC");
static_assert(offsetof(struct AudioPort__KAPC, Type) == 0x0, "AudioPort__KAPC.Type");
static_assert(offsetof(struct AudioPort__KAPC, AllFlags) == 0x1, "AudioPort__KAPC.AllFlags");
static_assert(offsetof(struct AudioPort__KAPC, Size) == 0x2, "AudioPort__KAPC.Size");
static_assert(offsetof(struct AudioPort__KAPC, SpareByte1) == 0x3, "AudioPort__KAPC.SpareByte1");
static_assert(offsetof(struct AudioPort__KAPC, SpareLong0) == 0x4, "AudioPort__KAPC.SpareLong0");
static_assert(offsetof(struct AudioPort__KAPC, Thread) == 0x8, "AudioPort__KAPC.Thread");
static_assert(offsetof(struct AudioPort__KAPC, ApcListEntry) == 0x10, "AudioPort__KAPC.ApcListEntry");
static_assert(offsetof(struct AudioPort__KAPC, Reserved) == 0x20, "AudioPort__KAPC.Reserved");
static_assert(offsetof(struct AudioPort__KAPC, NormalContext) == 0x38, "AudioPort__KAPC.NormalContext");
static_assert(offsetof(struct AudioPort__KAPC, SystemArgument1) == 0x40, "AudioPort__KAPC.SystemArgument1");
static_assert(offsetof(struct AudioPort__KAPC, SystemArgument2) == 0x48, "AudioPort__KAPC.SystemArgument2");
static_assert(offsetof(struct AudioPort__KAPC, ApcStateIndex) == 0x50, "AudioPort__KAPC.ApcStateIndex");
static_assert(offsetof(struct AudioPort__KAPC, ApcMode) == 0x51, "AudioPort__KAPC.ApcMode");
static_assert(offsetof(struct AudioPort__KAPC, Inserted) == 0x52, "AudioPort__KAPC.Inserted");
#endif

#ifndef NEVERD_TYPE_AudioPort__IRP
#define NEVERD_TYPE_AudioPort__IRP
// AudioPort__IRP: 0xD0 (208) bytes
struct DECLSPEC_ALIGN(16) AudioPort__IRP
{
    CSHORT Type;                                                // 0x00
    uint16_t Size;                                              // 0x02
    // 0x04: 4 bytes of padding
    PMDL MdlAddress;                                            // 0x08
    uint32_t Flags;                                             // 0x10
    // 0x14: 4 bytes of padding
    union
    {
        struct AudioPort__IRP *MasterIrp;                       // 0x18
        int32_t IrpCount;                                       // 0x18
        PVOID SystemBuffer;                                     // 0x18
    } AssociatedIrp;                                            // 0x18
    LIST_ENTRY ThreadListEntry;                                 // 0x20
    IO_STATUS_BLOCK IoStatus;                                   // 0x30
    KPROCESSOR_MODE RequestorMode;                              // 0x40
    AudioPort_BOOLEAN PendingReturned;                          // 0x41
    char StackCount;                                            // 0x42
    char CurrentLocation;                                       // 0x43
    AudioPort_BOOLEAN Cancel;                                   // 0x44
    KIRQL CancelIrql;                                           // 0x45
    CCHAR ApcEnvironment;                                       // 0x46
    uint8_t AllocationFlags;                                    // 0x47
    union                                                       // 0x48
    {
        PIO_STATUS_BLOCK UserIosb;                              // 0x48
        PVOID IoRingContext;                                    // 0x48
    };
    AudioPort_PKEVENT UserEvent;                                // 0x50
    union
    {
        struct
        {
            union                                               // 0x58
            {
                PIO_APC_ROUTINE UserApcRoutine;                 // 0x58
                PVOID IssuingProcess;                           // 0x58
            };
            union                                               // 0x60
            {
                PVOID UserApcContext;                           // 0x60
                struct _IORING_OBJECT *IoRing;                  // 0x60
            };
        } AsynchronousParameters;                               // 0x58
        LARGE_INTEGER AllocationSize;                           // 0x58
    } Overlay;                                                  // 0x58
    AudioPort_PDRIVER_CANCEL CancelRoutine;                     // 0x68
    PVOID UserBuffer;                                           // 0x70
    union
    {
        struct
        {
            union                                               // 0x78
            {
                AudioPort_KDEVICE_QUEUE_ENTRY DeviceQueueEntry; // 0x78
                struct                                          // 0x78
                {
                    PVOID DriverContext[4];                     // 0x78
                };
            };
            AudioPort_PETHREAD Thread;                          // 0x98
            PCHAR AuxiliaryBuffer;                              // 0xA0
            struct                                              // 0xA8
            {
                LIST_ENTRY ListEntry;                           // 0xA8
                union                                           // 0xB8
                {
                    struct AudioPort__IO_STACK_LOCATION *CurrentStackLocation; // 0xB8
                    uint32_t PacketType;                        // 0xB8
                };
            };
            AudioPort_PFILE_OBJECT OriginalFileObject;          // 0xC0
        } Overlay;                                              // 0x78
        AudioPort_KAPC Apc;                                     // 0x78
        PVOID CompletionKey;                                    // 0x78
    } Tail;                                                     // 0x78
};
static_assert(sizeof(struct AudioPort__IRP) == 0xD0, "AudioPort__IRP");
static_assert(offsetof(struct AudioPort__IRP, Type) == 0x0, "AudioPort__IRP.Type");
static_assert(offsetof(struct AudioPort__IRP, Size) == 0x2, "AudioPort__IRP.Size");
static_assert(offsetof(struct AudioPort__IRP, MdlAddress) == 0x8, "AudioPort__IRP.MdlAddress");
static_assert(offsetof(struct AudioPort__IRP, Flags) == 0x10, "AudioPort__IRP.Flags");
static_assert(offsetof(struct AudioPort__IRP, AssociatedIrp) == 0x18, "AudioPort__IRP.AssociatedIrp");
static_assert(offsetof(struct AudioPort__IRP, ThreadListEntry) == 0x20, "AudioPort__IRP.ThreadListEntry");
static_assert(offsetof(struct AudioPort__IRP, IoStatus) == 0x30, "AudioPort__IRP.IoStatus");
static_assert(offsetof(struct AudioPort__IRP, RequestorMode) == 0x40, "AudioPort__IRP.RequestorMode");
static_assert(offsetof(struct AudioPort__IRP, PendingReturned) == 0x41, "AudioPort__IRP.PendingReturned");
static_assert(offsetof(struct AudioPort__IRP, StackCount) == 0x42, "AudioPort__IRP.StackCount");
static_assert(offsetof(struct AudioPort__IRP, CurrentLocation) == 0x43, "AudioPort__IRP.CurrentLocation");
static_assert(offsetof(struct AudioPort__IRP, Cancel) == 0x44, "AudioPort__IRP.Cancel");
static_assert(offsetof(struct AudioPort__IRP, CancelIrql) == 0x45, "AudioPort__IRP.CancelIrql");
static_assert(offsetof(struct AudioPort__IRP, ApcEnvironment) == 0x46, "AudioPort__IRP.ApcEnvironment");
static_assert(offsetof(struct AudioPort__IRP, AllocationFlags) == 0x47, "AudioPort__IRP.AllocationFlags");
static_assert(offsetof(struct AudioPort__IRP, UserIosb) == 0x48, "AudioPort__IRP.UserIosb");
static_assert(offsetof(struct AudioPort__IRP, IoRingContext) == 0x48, "AudioPort__IRP.IoRingContext");
static_assert(offsetof(struct AudioPort__IRP, UserEvent) == 0x50, "AudioPort__IRP.UserEvent");
static_assert(offsetof(struct AudioPort__IRP, Overlay) == 0x58, "AudioPort__IRP.Overlay");
static_assert(offsetof(struct AudioPort__IRP, CancelRoutine) == 0x68, "AudioPort__IRP.CancelRoutine");
static_assert(offsetof(struct AudioPort__IRP, UserBuffer) == 0x70, "AudioPort__IRP.UserBuffer");
static_assert(offsetof(struct AudioPort__IRP, Tail) == 0x78, "AudioPort__IRP.Tail");
#endif


/* neverd.image: 0x180000000 (original loaded image storage) */
extern uint8_t unk_180000000[8612];
extern __typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) PcAddAdapterDevice(struct AudioPort__DRIVER_OBJECT *DriverObject, struct AudioPort__DEVICE_OBJECT *PhysicalDeviceObject, __typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) (*StartDevice)(struct AudioPort__DEVICE_OBJECT *DeviceObject, struct AudioPort__IRP *Irp, struct IResourceList *ResourceList), __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) MaxObjects, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) DeviceExtensionSize);
uint64_t UseAudioAdapter(AudioPort__DRIVER_OBJECT* arg0, AudioPort__DEVICE_OBJECT* arg1, void* arg2, uint32_t arg3, uint64_t arg4) {
    uint64_t icall_image_target1;
    uint64_t call0;

    icall_image_target1 = 0;
    __builtin_memcpy(&icall_image_target1, (unk_180000000 + 8464), 8);
    call0 = ((uint64_t)(uint32_t)(PcAddAdapterDevice((struct AudioPort__DRIVER_OBJECT *)(uintptr_t)((uint64_t)arg0), (struct AudioPort__DEVICE_OBJECT *)(uintptr_t)((uint64_t)arg1), (__typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) (*)(struct AudioPort__DEVICE_OBJECT *DeviceObject, struct AudioPort__IRP *Irp, struct IResourceList *ResourceList))(uintptr_t)((uint64_t)arg2), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)))(uintptr_t)(arg3), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)))(uintptr_t)((uint32_t)(arg4)))));
    return call0;
}
