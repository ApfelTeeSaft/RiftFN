#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <emmintrin.h>  // SSE2
#include <smmintrin.h>  // SSE4.1

// Forward declarations for UE4 types
using UObject = void;
using UFunction = void;
using UWorld = void;
using FString = void;

// Global resolved addresses (from pattern scanning)
// Variable names match IDA labels, addresses in comments
namespace Globals {
    extern int    dword_18004FDE0;    // EngineVersion (parsed numeric)
    extern __int64 qword_18004FDD8;  // GObjects (resolved address)
    extern __int64 qword_18004FDB0;  // GWorld (resolved address)
    extern __int64 qword_18004FDC8;  // FNameToString (resolved address)
    extern __int64 qword_18004FDA8;  // InputKey (resolved address)
    extern __int64 qword_18004FDC0;  // EngineVersionFunc pointer
    extern __int64 (__fastcall *qword_18004FDE8)
        (__int64, __int64, __int64, __int64);  // ProcessEvent func ptr
    extern __int64 qword_18004FDF0;  // PatternLink struct pointer
    extern __int64 (__fastcall *qword_18004FDB8)
        (uint64_t, uint64_t, uint64_t);  // AdditionalHookFunc
    extern __int64 qword_18004FDD0;  // AdditionalAddr
    extern __int64 qword_18004FFF0;  // Console function address (for sub_18000E8A0)

    // Version config tree (std::map-like, MSVC red-black tree)
    extern __int64 qword_180050050;  // Tree head node pointer
    extern __int64 qword_180050058;  // Tree size

    // SSE capability flag (from __isa_available)
    extern int    dword_18004F028;   // SSE level (__isa_available)
}
