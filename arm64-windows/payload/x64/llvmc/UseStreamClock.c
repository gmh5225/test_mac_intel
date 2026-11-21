#include <stdint.h>


typedef struct _HW_TIME_CONTEXT _HW_TIME_CONTEXT;
void StreamClassQueryMasterClockSync(void *MasterClockHandle, struct _HW_TIME_CONTEXT *TimeContext);
void UseStreamClock(void* arg0, _HW_TIME_CONTEXT* arg1) {
    StreamClassQueryMasterClockSync((void *)(uintptr_t)((uint64_t)arg0), (struct _HW_TIME_CONTEXT *)(uintptr_t)((uint64_t)arg1));
    return;
}
