/* WDK DRIVER_INITIALIZE forwards the two incoming pointers and its NTSTATUS. */
#include <stdint.h>

extern void neverd_cookie(void);
extern int32_t neverd_driver_entry(void *driver, void *registry_path);

__attribute__((target("branch-protection=pac-ret+b-key")))
int32_t QUALIFIED_SHIM(void *driver, void *registry_path) {
    neverd_cookie();
    return neverd_driver_entry(driver, registry_path);
}
