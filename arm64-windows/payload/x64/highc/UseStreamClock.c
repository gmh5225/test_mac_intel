typedef struct _HW_TIME_CONTEXT _HW_TIME_CONTEXT;

#include <stdint.h>

extern void StreamClassQueryMasterClockSync(void *MasterClockHandle, struct _HW_TIME_CONTEXT *TimeContext);

/* neverd.entry: 0x180001030 */
void UseStreamClock(void* arg0, _HW_TIME_CONTEXT* arg1) {
    StreamClassQueryMasterClockSync(arg0, arg1);
    return;
}
