#pragma once

#include "globals.h"
#include "pattern_scan.h"

namespace GameLogic {
    // Main game setup - called after GWorld is valid.
    // Original: sub_1800282B0 (never returns)
    //
    // Flow:
    //   1. Version 3700114 (v1.7.2): patch specific function to RET
    //   2. Versions 5914491-14801545: decrypt+scan patterns, patch bytes
    //   3. All versions: decrypt+scan 95-byte + 84-byte patterns
    //      to resolve AdditionalHookFunc and AdditionalAddr
    //   4. Call InitializeSDK (sub_180007CB0)
    //   5. Call InitConsoleAndViewport (sub_18000E8A0)
    //   6. Enter main game loop (sub_180025720, never returns)
    [[noreturn]] void MainGameSetup();

    // Main game interaction loop.
    // Original: sub_180025720 (never returns)
    // IDA decompilation failed (frame error), reconstructed as stub.
    // Handles input processing, game commands, and state management.
    [[noreturn]] void MainGameLoop();
}
