/*
 * Rift DLL - Pattern Scanning Engine
 *
 * Original functions:
 *   sub_180026F70 - Pattern string parser (hex pattern -> int vector)
 *   Inline scanning loops in StartAddress (0x1800291A0) and
 *   sub_180027620 (InitializePatterns)
 *
 * The scanning logic is inlined by the compiler in the original binary,
 * appearing as repeated loop structures. We factor it out here.
 */

#include "pattern_scan.h"
#include <cstdlib>
#include <cstring>

namespace PatternScan {

// Original: sub_180026F70
// Parses IDA-style hex pattern string into a vector of ints.
// '?' and '??' map to -1 (wildcard). Hex values parsed via strtoul(..., 16).
// The original function takes (unused, result_ptr, pattern_str) and writes
// to a std::vector<int> at result_ptr. We return by value here.
std::vector<int> ParsePattern(const char* pattern)
{
    std::vector<int> result;
    const char* p = pattern;
    size_t len = strlen(pattern);
    const char* end_ptr = pattern + len;
    char* next = const_cast<char*>(pattern);

    if (p < end_ptr)
    {
        do
        {
            if (*p == '?')
            {
                next = const_cast<char*>(p) + 1;
                if (p[1] == '?')
                    next = const_cast<char*>(p) + 2;
                result.push_back(-1);
            }
            else
            {
                unsigned int val = strtoul(p, &next, 16);
                result.push_back(static_cast<int>(val));
            }
            p = next + 1;
            next = const_cast<char*>(p);
        }
        while (p < end_ptr);
    }

    return result;
}

// Pattern scan: linear scan through module memory
// Matches the exact loop structure from StartAddress and sub_180027620:
//   for each offset in [0, sizeOfImage - patternSize):
//     for each byte in pattern:
//       if module[offset+j] != pattern[j] && pattern[j] != -1: break
//     if all matched: return base + offset
//
// The original uses SizeOfImage from PE optional header as scan range.
uintptr_t FindPatternRaw(HMODULE module, const std::vector<int>& pattern)
{
    if (pattern.empty())
        return 0;

    auto base = reinterpret_cast<const unsigned char*>(module);

    // Read SizeOfImage from PE header (matching original: v2 = *((int*)module + 15))
    // ((int*)module + 15) = offset 60 = e_lfanew
    __int64 e_lfanew = *reinterpret_cast<const int*>(
        reinterpret_cast<const char*>(module) + 60);
    unsigned __int64 sizeOfImage = *reinterpret_cast<const unsigned int*>(
        reinterpret_cast<const char*>(module) + e_lfanew + 80);

    unsigned __int64 patternSize = pattern.size();
    unsigned __int64 scanRange = sizeOfImage - patternSize;

    if (!scanRange)
        return 0;

    unsigned int matchIdx = 0;
    unsigned int scanOffset = 0;

    if (patternSize)
    {
        while (true)
        {
            unsigned __int64 j = 0;
            while (true)
            {
                int patByte = pattern[j];
                if (base[matchIdx + scanOffset] != static_cast<unsigned char>(patByte)
                    && patByte != -1)
                    break;
                j = ++matchIdx;
                if (matchIdx >= patternSize)
                    goto found;
            }
            if (++scanOffset >= scanRange)
                return 0;
            matchIdx = 0;
        }
    }

found:
    return reinterpret_cast<uintptr_t>(base + scanOffset);
}

// Find pattern with RIP-relative offset resolution
// offset_a: if non-zero, read RIP-relative int32 at (result + offset_a),
//           then result = result + offset_a + rip_offset + 4
// offset_b: if non-zero, add to result
uintptr_t FindPattern(HMODULE module, const char* patternStr,
                      int offset_a, int offset_b)
{
    auto pattern = ParsePattern(patternStr);
    uintptr_t addr = FindPatternRaw(module, pattern);

    if (!addr)
        return 0;

    // Apply RIP-relative resolution (matching original logic)
    if (offset_a)
    {
        int32_t ripOffset = *reinterpret_cast<int32_t*>(addr + offset_a);
        addr = addr + offset_a + ripOffset + 4;
    }

    // Apply additional offset
    if (offset_b)
        addr += offset_b;

    return addr;
}

} // namespace PatternScan
