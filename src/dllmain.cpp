/*
 * Rift DLL - DLL Entry Point and Main Thread
 *
 * Original functions:
 *   DllMain at 0x1800295F0
 *   StartAddress at 0x1800291A0
 *
 * DllMain creates a thread running StartAddress on DLL_PROCESS_ATTACH.
 * StartAddress sleeps 10s, pattern scans for EngineVersion, parses the
 * version string, calls InitializePatterns, waits for GWorld, then
 * calls MainGameSetup.
 */

#include "globals.h"
#include "pattern_scan.h"
#include "version_config.h"
#include "string_utils.h"
#include "game_logic.h"

#include <cstdlib>
#include <cerrno>

// ============================================================================
// Global variable definitions
// Addresses match the original binary's .data section layout
// ============================================================================
namespace Globals {
    int    dword_18004FDE0 = 0;      // EngineVersion (parsed CL number)
    __int64 qword_18004FDD8 = 0;     // GObjects (resolved address)
    __int64 qword_18004FDB0 = 0;     // GWorld (resolved address)
    __int64 qword_18004FDC8 = 0;     // FNameToString (resolved address)
    __int64 qword_18004FDA8 = 0;     // InputKey (resolved address)
    __int64 qword_18004FDC0 = 0;     // EngineVersionFunc pointer
    __int64 (__fastcall *qword_18004FDE8)
        (__int64, __int64, __int64, __int64) = nullptr;  // ProcessEvent
    __int64 qword_18004FDF0 = 0;     // PatternLink struct pointer
    __int64 (__fastcall *qword_18004FDB8)
        (uint64_t, uint64_t, uint64_t) = nullptr;  // AdditionalHookFunc
    __int64 qword_18004FDD0 = 0;     // AdditionalAddr
    __int64 qword_18004FFF0 = 0;     // Console function address
    __int64 qword_180050050 = 0;     // VersionConfigHead
    __int64 qword_180050058 = 0;     // VersionConfigSize
    int    dword_18004F028 = 0;      // SSE capability (__isa_available)
}

// ============================================================================
// StartAddress - Main thread entry point
// Original: 0x1800291A0
//
// Reconstructed flow matching the IDA decompilation:
//   1. Sleep(0x2710) = 10000ms
//   2. GetModuleHandleW(0) twice (first result discarded)
//   3. Read PE header: e_lfanew, SizeOfImage
//   4. Parse engine version pattern "40 53 48 83 EC 20 ..."
//   5. Linear scan through module for pattern match
//   6. Call found function to get version string
//   7. Convert wide string to narrow via sub_180005030
//   8. Split on "-" via sub_180004DE0, extract second part
//   9. Split again on "-", extract first part (CL number)
//   10. strtol(clString, &endPtr, 10) -> dword_18004FDE0
//   11. Call sub_180027620 (InitializePatterns)
//   12. Wait for GWorld (poll every 1000ms)
//   13. Sleep(5000ms)
//   14. Call sub_1800282B0 (MainGameSetup) - never returns
// ============================================================================
static void WINAPI StartAddress(LPVOID lpThreadParameter)
{
    // Step 1: Wait for game initialization
    Sleep(0x2710u);

    // Step 2: Get game module base (two calls, matching original)
    GetModuleHandleW(nullptr);
    HMODULE gameModule = GetModuleHandleW(nullptr);

    // Step 3: Parse PE header
    // Original: v2 = *((int *)ModuleHandleW + 15)  =>  offset 60 = e_lfanew
    // Original: v3 = *(unsigned int *)((char *)ModuleHandleW + v2 + 80)  =>  SizeOfImage
    __int64 e_lfanew = *reinterpret_cast<int*>(
        reinterpret_cast<char*>(gameModule) + 60);
    __int64 sizeOfImage = *reinterpret_cast<unsigned int*>(
        reinterpret_cast<char*>(gameModule) + e_lfanew + 80);

    // Step 4: Parse pattern and set up scan
    std::vector<int> parsedPattern;
    parsedPattern.reserve(32);  // pre-allocate
    // Original: sub_180026F70 called with pattern string, result stored in Block
    {
        // Inline equivalent of sub_180026F70
        const char* patternStr =
            "40 53 48 83 EC 20 48 8B D9 E8 ? ? ? ? 48 8B C8 41 B8 04 ? ? ? 48 8B D3";
        parsedPattern = PatternScan::ParsePattern(patternStr);
    }

    auto base = reinterpret_cast<const unsigned char*>(gameModule);
    unsigned __int64 patternSize = parsedPattern.size();
    unsigned __int64 scanRange = sizeOfImage - patternSize;

    // Step 5: Linear scan (exact loop structure from original)
    __int64 (__fastcall *engineVersionFunc)(unsigned char*) = nullptr;

    if (scanRange)
    {
        unsigned int matchIdx = 0;
        unsigned int scanOffset = 0;

        if (patternSize)
        {
            while (true)
            {
                __int64 j = 0;
                while (true)
                {
                    int patByte = parsedPattern[j];
                    if (base[matchIdx + scanOffset] !=
                            static_cast<unsigned char>(patByte)
                        && patByte != -1)
                        break;
                    j = ++matchIdx;
                    if (matchIdx >= patternSize)
                    {
                        engineVersionFunc = reinterpret_cast<
                            decltype(engineVersionFunc)>(
                            const_cast<unsigned char*>(base + scanOffset));
                        goto pattern_found;
                    }
                }
                if (++scanOffset >= scanRange)
                    break;
                matchIdx = 0;
            }
        }
    }

    // Pattern not found
    MessageBoxA(nullptr,
        "Rift cannot start due to a pattern mismatch. Please try another version.",
        "Error", MB_ICONERROR);

    // Original: if pattern not found, Block is freed, engineVersionFunc = 0
    engineVersionFunc = nullptr;

pattern_found:
    // Step 6: Store function pointer globally
    Globals::qword_18004FDC0 = reinterpret_cast<__int64>(engineVersionFunc);

    // Step 7: Call EngineVersion function and parse version string
    // Original flow:
    //   v13 = engineVersionFunc(v29)  // v29 is 16-byte stack buffer
    //   sub_180005030(v13, String)    // wide-to-narrow conversion
    //   sub_180004DE0(Block, String, "-")  // split on '-'
    //   copy second element of Block into String
    //   sub_180004DE0(Src, String, "-")   // split again on '-'
    //   copy first element of Src into String
    //   strtol(String, &EndPtr, 10) -> dword_18004FDE0
    if (engineVersionFunc)
    {
        unsigned char tempBuf[16] = {0};
        auto* versionResult = engineVersionFunc(tempBuf);

        // The function returns a wide string structure.
        // sub_180005030 narrows it to ASCII.
        // For reconstruction: we interpret the result as pointing to
        // a std::wstring-like structure.
        auto* wstrPtr = reinterpret_cast<wchar_t**>(versionResult);
        wchar_t* wstr = *wstrPtr;
        size_t wlen = 0;
        while (wstr[wlen]) ++wlen;

        std::string versionString = StringUtils::WideToNarrow(wstr, wlen);

        // First split on '-': extracts parts like
        // "4.21.0" and "4204761+++Fortnite+Release" etc.
        auto parts1 = StringUtils::SplitString(versionString, '-');

        // Copy second element (index 1) as the new string
        if (parts1.size() > 1)
        {
            std::string secondPart = parts1[1];

            // Second split on '-': extract the CL number
            auto parts2 = StringUtils::SplitString(secondPart, '-');

            if (!parts2.empty())
            {
                const char* numStr = parts2[0].c_str();
                char* endPtr = nullptr;

                // Original: errno check + strtol + error handling
                int* errnoPtr = &errno;
                *errnoPtr = 0;
                int version = static_cast<int>(strtol(numStr, &endPtr, 10));

                if (numStr == endPtr)
                {
                    // std::_Xinvalid_argument("invalid stoi argument")
                    // Original calls __debugbreak() after this
                }
                if (*errnoPtr == ERANGE)
                {
                    // std::_Xout_of_range("stoi argument out of range")
                }

                Globals::dword_18004FDE0 = version;
            }
        }
    }

    // Step 8: Initialize version configs and resolve patterns
    VersionManager::InitVersionConfigs();
    VersionManager::InitializePatterns();

    // Step 9: Wait for GWorld to be valid
    // Original: while ( !*(_QWORD *)qword_18004FDB0 ) Sleep(0x3E8u);
    while (!*reinterpret_cast<__int64*>(Globals::qword_18004FDB0))
        Sleep(0x3E8u);

    // Step 10: Wait for world stabilization
    Sleep(0x1388u);

    // Step 11: Enter main game setup (never returns)
    // Original: sub_1800282B0()
    GameLogic::MainGameSetup();
}

// ============================================================================
// DllMain - DLL Entry Point
// Original: 0x1800295F0
//
// On DLL_PROCESS_ATTACH (fdwReason == 1):
//   CreateThread(0, 0, StartAddress, hinstDLL, 0, 0)
// Always returns TRUE.
// ============================================================================
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == 1)
        CreateThread(nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(StartAddress),
            hinstDLL, 0, nullptr);
    return TRUE;
}
