#include <stdbool.h>
#include <windows.h>
#include <bcp47mrm.h>
__declspec(dllexport) bool InspectIsWellFormedTag(PCWSTR tag) {
    return IsWellFormedTag(tag);
}
