typedef struct AudioPort__DRIVER_OBJECT AudioPort__DRIVER_OBJECT;
typedef struct AudioPort__DEVICE_OBJECT AudioPort__DEVICE_OBJECT;
typedef struct AudioPort__IRP AudioPort__IRP;
typedef struct IResourceList IResourceList;

#include <stdint.h>
#include <string.h>

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */

extern __typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) PcAddAdapterDevice(struct AudioPort__DRIVER_OBJECT *DriverObject, struct AudioPort__DEVICE_OBJECT *PhysicalDeviceObject, __typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) (*StartDevice)(struct AudioPort__DEVICE_OBJECT *DeviceObject, struct AudioPort__IRP *Irp, struct IResourceList *ResourceList), __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) MaxObjects, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) DeviceExtensionSize);

/* neverd.entry: 0x180001010 */
int64_t UseAudioAdapter(AudioPort__DRIVER_OBJECT* arg0, AudioPort__DEVICE_OBJECT* arg1, void* arg2, int32_t arg3, int64_t arg4) {
    return (uint64_t)((uint32_t)PcAddAdapterDevice(arg0, arg1, arg2, arg3, arg4));
}
