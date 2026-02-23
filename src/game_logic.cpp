/*
 * Rift DLL - Game Logic
 *
 * Implements the main game setup flow and game interaction loop.
 *
 * Original function: sub_1800282B0 (MainGameSetup) - never returns.
 *
 * The function performs version-specific patching and hook installation,
 * then initializes the UE4 SDK, sets up the console/viewport, and enters
 * the main game loop.
 *
 * Version handling:
 *   - 3700114 (v1.7.2): Patches a specific function to RET (0xC3)
 *   - 5914491-14801545: Applies byte patches via encrypted pattern scans
 *   - All versions: Resolves AdditionalHookFunc and AdditionalAddr,
 *                   then initializes SDK, console, and enters game loop
 *
 * The main game loop (sub_180025720) could not be decompiled by IDA
 * (function frame error) and is reconstructed as a stub. TODO: figure out wtf is going on
 */

#include "game_logic.h"
#include "hooks.h"
#include "ue4_sdk.h"

namespace GameLogic {

// Original: sub_1800282B0
// This is the main game setup function called from StartAddress after GWorld
// is detected as valid. The function never returns.
//
// Full control flow from IDA decompilation:
//
//   1. if (version == 3700114):
//        Pattern scan "48 89 5C 24 10 57 48 83 EC 60 49 8B F8 48 8B DA 4C"
//        Patch first byte to 0xC3 (RET) using VirtualProtect
//        (Disables a specific function in the game for v1.7.2 compatibility)
//
//   2. if ((unsigned)(version - 5914491) <= 0x87618A):
//        [Versions 5914491 to 14801545]
//        Decrypt 64-byte encrypted pattern (xmmword_1800461D0..180046200)
//        Pattern scan in game module
//        Store result address + 23 as patch target
//        Decrypt 45-byte encrypted pattern (xmmword_180046FD0 + data)
//        Pattern scan in game module
//        *patchTarget = 2  (patch byte at offset +23 of first pattern)
//        *(result2 + 6) = 2  (patch byte at offset +6 of second pattern)
//
//   3. [All versions reach here - LABEL_72 in IDA]
//        Decrypt 95-byte encrypted pattern (xmmword_180046990..1800469D0)
//        Pattern scan -> resolve qword_18004FDB8 (AdditionalHookFunc)
//        Decrypt 84-byte encrypted pattern (xmmword_180046AC0..180046B00)
//        Pattern scan -> resolve qword_18004FDD0 (AdditionalAddr)
//
//   4. [LABEL_113 - Final initialization]
//        qword_18004FDD0 = resolved address
//        Call sub_180007CB0 (InitializeSDK)
//        Call sub_18000E8A0 (InitConsoleAndViewport)
//        Call sub_180025720 (MainGameLoop - never returns)

[[noreturn]] void MainGameSetup()
{
    int version = Globals::dword_18004FDE0;

    // ========================================================================
    // Step 1: Version 3700114 (v1.7.2) special handling
    // Patches a specific function to return immediately (0xC3 = RET)
    // Original: inline pattern scan with hardcoded string, VirtualProtect
    // ========================================================================
    if (version == 3700114)
    {
        HMODULE gameModule = GetModuleHandleW(nullptr);
        uintptr_t addr = PatternScan::FindPattern(gameModule,
            "48 89 5C 24 10 57 48 83 EC 60 49 8B F8 48 8B DA 4C");

        if (addr)
        {
            DWORD oldProtect;
            VirtualProtect(reinterpret_cast<void*>(addr), 1,
                           PAGE_EXECUTE_READWRITE, &oldProtect);
            *reinterpret_cast<uint8_t*>(addr) = 0xC3;
            DWORD temp;
            VirtualProtect(reinterpret_cast<void*>(addr), 1, oldProtect, &temp);
        }
        else
        {
            MessageBoxA(nullptr,
                "Rift cannot start due to a pattern mismatch. "
                "Please try another version.",
                "Error", MB_ICONERROR);
        }
    }

    // ========================================================================
    // Steps 2 & 3: Apply version-specific hooks
    // Hooks::ApplyHooks handles both:
    //   - Version range byte patches (step 2)
    //   - AdditionalHookFunc/AdditionalAddr resolution (step 3)
    // ========================================================================
    Hooks::ApplyHooks(version);

    // ========================================================================
    // Step 4: Initialize UE4 SDK
    // Original: sub_180007CB0
    // Resolves all UE4 property offsets needed for game interaction
    // ========================================================================
    UE4::InitializeSDK();

    // ========================================================================
    // Step 5: Initialize console and viewport
    // Original: sub_18000E8A0
    // Sets up the console object and assigns it to the viewport
    // ========================================================================
    UE4::InitConsoleAndViewport();

    // ========================================================================
    // Step 6: Enter main game loop (never returns)
    // Original: sub_180025720
    // ========================================================================
    MainGameLoop();
}

// Original: sub_180025720
// IDA decompilation failed with "function frame is wrong" error.
// This is the core game interaction loop that:
//   - Processes player input via InputKey (qword_18004FDA8)
//   - Executes game commands via ProcessEvent
//   - Manages game state (inventory, building, weapons, etc.)
//   - Calls AdditionalHookFunc (qword_18004FDB8) for extended functionality
//   - Never returns
//
// Full reconstruction requires further analysis lol.
[[noreturn]] void MainGameLoop()
{
    // The original function enters an infinite processing loop that
    // handles game state and user interaction. Since IDA could not
    // produce pseudocode (frame error), this remains a stub.
    while (true)
        Sleep(1000);
}

} // namespace GameLogic
