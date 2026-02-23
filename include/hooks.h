#pragma once

#include "globals.h"

namespace Hooks {
    // Decrypt an encrypted pattern string using the XOR cipher
    // Key: (i % 51) + 52 per byte
    // Uses SSE2 vectorized implementation when available
    // Original: inline code in sub_1800282B0 and sub_180001020
    void DecryptPattern(char* buffer, int length);

    // Apply version-specific patches/hooks
    // Called from MainGameSetup (sub_1800282B0)
    void ApplyHooks(int engineVersion);

    // Patch a single byte in memory using VirtualProtect
    bool PatchByte(void* address, uint8_t value);
}
