#pragma once

#include "globals.h"
#include <vector>
#include <string>

namespace PatternScan {
    // Parse a pattern string ("48 8B ? ? 01") into an int vector
    // -1 entries are wildcards (? or ??)
    // Original: sub_180026F70
    std::vector<int> ParsePattern(const char* pattern);

    // Find pattern in module memory using linear scan
    // Returns offset from module base where pattern was found, or 0 on failure
    // Original: inline pattern scanning loop used in StartAddress and sub_180027620
    uintptr_t FindPattern(HMODULE module, const char* patternStr,
                          int offset_a = 0, int offset_b = 0);

    // Find pattern from pre-parsed int vector
    // Returns offset from module base, or 0 on failure
    uintptr_t FindPatternRaw(HMODULE module, const std::vector<int>& pattern);
}
