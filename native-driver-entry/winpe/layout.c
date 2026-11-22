/* Compile against Microsoft's original ARM64 WDK headers. */
#include <ntifs.h>
#include "layout.h"
_Static_assert(sizeof(void *) == 8 && sizeof(WCHAR) == 2, "ARM64 data model");
_Static_assert(__builtin_offsetof(DRIVER_OBJECT, DriverStart) == DRIVER_START_OFFSET, "DriverStart offset");
_Static_assert(__builtin_offsetof(UNICODE_STRING, Buffer) == UNICODE_BUFFER_OFFSET, "Unicode buffer offset");
_Static_assert(IO_TYPE_DRIVER == DRIVER_TYPE, "Driver object type");
