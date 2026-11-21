#pragma once

#include <windows.h>

struct detach_record {
    UINT_PTR module;
    UINT_PTR reason;
    UINT_PTR reserved;
};
