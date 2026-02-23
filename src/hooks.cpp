/*
 * Rift DLL - Hooking and Pattern Decryption
 *
 * Implements the SSE2 XOR cipher for encrypted pattern strings
 * and version-specific hook installation.
 *
 * Original: Inline code in sub_1800282B0 (MainGameSetup)
 *
 * Encrypted pattern data extracted directly from Yosemite.dll .rdata section.
 * Decryption: XOR each byte with key[i] where key[i] = (i % 51) + 52
 */

#include "hooks.h"
#include "pattern_scan.h"
#include <emmintrin.h>  // SSE2
#include <smmintrin.h>  // SSE4.1
#include <cstring>

// ============================================================================
// Encrypted pattern blobs from .rdata (extracted from binary)
// These are XOR-encrypted with key (i % 51) + 52
// ============================================================================

// 64-byte encrypted pattern (xmmword_1800461D0..180046200)
// Decrypts to: "48 8B C8 48 8B 47 30 48 39 14 C8 0F 85 ? ? ? ? 80 BE ? ? ? ? 03"
// Used for versions: general (5914491 - 14801545 range)
static unsigned char encrypted_pattern_64[64] = {
    0x00, 0x0D, 0x16, 0x0F, 0x7A, 0x19, 0x79, 0x03,
    0x1C, 0x09, 0x06, 0x1F, 0x78, 0x03, 0x62, 0x77,
    0x73, 0x65, 0x75, 0x77, 0x68, 0x7D, 0x72, 0x6B,
    0x7F, 0x74, 0x6E, 0x7E, 0x64, 0x71, 0x11, 0x6B,
    0x74, 0x65, 0x10, 0x77, 0x60, 0x6C, 0x7A, 0x64,
    0x7C, 0x62, 0x7E, 0x60, 0x40, 0x5E, 0x42, 0x5B,
    0x54, 0x45, 0x24, 0x71, 0x15, 0x09, 0x17, 0x07,
    0x19, 0x05, 0x1B, 0x03, 0x1D, 0x0E, 0x0C, 0x40,
};

// 95-byte encrypted pattern (xmmword_180046990..1800469D0 + 15 bytes)
// Decrypts to: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F1 41 8B D8 48 8B 0D ? ? ? ? 48 8B FA 48 85 C9"
// Used for AdditionalHookFunc (qword_18004FDB8)
static unsigned char encrypted_pattern_95[95] = {
    0x00, 0x0D, 0x16, 0x0F, 0x01, 0x19, 0x0F, 0x78,
    0x1C, 0x0F, 0x0A, 0x1F, 0x7F, 0x61, 0x76, 0x7B,
    0x64, 0x7D, 0x7F, 0x67, 0x7F, 0x7D, 0x6A, 0x79,
    0x78, 0x6D, 0x71, 0x6F, 0x65, 0x66, 0x72, 0x67,
    0x6C, 0x75, 0x6E, 0x64, 0x78, 0x1C, 0x19, 0x7B,
    0x63, 0x7D, 0x6A, 0x67, 0x40, 0x59, 0x20, 0x43,
    0x22, 0x54, 0x46, 0x00, 0x04, 0x16, 0x0F, 0x7A,
    0x19, 0x7E, 0x03, 0x1C, 0x09, 0x06, 0x1F, 0x78,
    0x03, 0x62, 0x73, 0x00, 0x65, 0x79, 0x67, 0x77,
    0x69, 0x75, 0x6B, 0x73, 0x6D, 0x7A, 0x77, 0x70,
    0x69, 0x10, 0x73, 0x12, 0x14, 0x76, 0x63, 0x60,
    0x79, 0x62, 0x6E, 0x7C, 0x1E, 0x67, 0x5F,
};

// 84-byte encrypted pattern (xmmword_180046AC0..180046B00 + 4 bytes)
// Decrypts to: "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 48 8D 68 ? 48 81 EC ? ? ? ? 48 8B ? 7F"
// Used for AdditionalAddr (qword_18004FDD0)
static unsigned char encrypted_pattern_84[84] = {
    0x00, 0x0D, 0x16, 0x0F, 0x7A, 0x19, 0x79, 0x0F,
    0x1C, 0x09, 0x06, 0x1F, 0x78, 0x78, 0x62, 0x76,
    0x7C, 0x65, 0x79, 0x67, 0x7C, 0x71, 0x6A, 0x73,
    0x75, 0x6D, 0x79, 0x7F, 0x70, 0x6E, 0x72, 0x67,
    0x6C, 0x75, 0x6E, 0x6E, 0x78, 0x6E, 0x62, 0x7B,
    0x63, 0x7D, 0x6B, 0x6A, 0x40, 0x55, 0x5A, 0x43,
    0x5C, 0x21, 0x46, 0x02, 0x0D, 0x16, 0x08, 0x18,
    0x0D, 0x02, 0x1B, 0x04, 0x0C, 0x1E, 0x7A, 0x03,
    0x61, 0x7D, 0x63, 0x7B, 0x65, 0x79, 0x67, 0x77,
    0x69, 0x7E, 0x73, 0x6C, 0x75, 0x0C, 0x6F, 0x6F,
    0x71, 0x65, 0x15, 0x54,
};

// 45-byte encrypted pattern (xmmword_180046FD0 + associated data)
// Decrypts to: "80 BB ? ? ? ? 03 75 ? 8B 83 ? ? ? ? 48 8B CB"
// Used for specific version range byte patching
static unsigned char encrypted_pattern_45[45] = {
    0x0C, 0x05, 0x16, 0x75, 0x7A, 0x19, 0x05, 0x1B,
    0x03, 0x1D, 0x01, 0x1F, 0x7F, 0x61, 0x72, 0x70,
    0x64, 0x72, 0x73, 0x67, 0x77, 0x69, 0x72, 0x09,
    0x6C, 0x75, 0x7D, 0x6F, 0x6F, 0x71, 0x6D, 0x73,
    0x6B, 0x75, 0x69, 0x77, 0x6C, 0x61, 0x7A, 0x63,
    0x1E, 0x7D, 0x1D, 0x1D, 0x60,
};

namespace Hooks {

// Decrypt an encrypted pattern string using XOR cipher.
// Key per byte: (i % 51) + 52
//
// Original uses SSE2/SSE4.1 vectorized implementation when dword_18004F028 >= 2:
//   - Processes 8 bytes per iteration (two groups of 4 via SIMD)
//   - Computes i % 51 using multiplication by magic 0xA0A0A0A1
//   - Packs result to bytes, adds 52, XORs with buffer
//   - Scalar fallback for remaining bytes
void DecryptPattern(char* buffer, int length)
{
    int i = 0;

    // SSE2 vectorized path (when __isa_available >= 2, matching original)
    if (Globals::dword_18004F028 >= 2)
    {
        __m128i indices_base = _mm_setr_epi32(0, 1, 2, 3);      // xmmword_180047BE0
        __m128i divisor_magic = _mm_set1_epi32(0xA0A0A0A1u);    // xmmword_180047CD0
        __m128i modulus = _mm_set1_epi32(51);                     // xmmword_180047C00
        __m128i add_const;                                        // xmmword_180047C70
        memset(&add_const, 0x34, sizeof(add_const));              // 0x34 = 52
        __m128i mask = _mm_set1_epi16(0x00FF);                   // xmmword_180047C60
        __m128i shift5 = _mm_cvtsi32_si128(5);
        __m128i shift31 = _mm_cvtsi32_si128(31);
        unsigned int addVal = 0x34343434u;  // cast for XOR

        char* ptr = buffer + 4;

        while (i + 8 <= length)
        {
            ptr += 8;

            // First group of 4 indices
            __m128i idx = _mm_add_epi32(
                _mm_shuffle_epi32(_mm_cvtsi32_si128(i), 0),
                indices_base);
            __m128i idx2 = _mm_add_epi32(
                _mm_shuffle_epi32(_mm_cvtsi32_si128(i + 4), 0),
                indices_base);
            i += 8;

            // Compute idx % 51 using multiply-high trick
            __m128i hi = (__m128i)_mm_shuffle_ps(
                (__m128)_mm_mul_epi32(_mm_unpacklo_epi32(idx, idx), divisor_magic),
                (__m128)_mm_mul_epi32(_mm_unpackhi_epi32(idx, idx), divisor_magic),
                221);
            __m128i q = _mm_sra_epi32(_mm_add_epi32(hi, idx), shift5);
            q = _mm_add_epi32(_mm_srl_epi32(q, shift31), q);
            __m128i rem = _mm_sub_epi32(idx, _mm_mullo_epi32(q, modulus));

            // Pack remainder to bytes and add 52
            __m128i packed = _mm_and_si128(
                _mm_shuffle_epi32(
                    _mm_shufflehi_epi16(
                        _mm_shufflelo_epi16(rem, 0xD8), 0xD8), 0xD8),
                mask);
            __m128i key = _mm_add_epi8(
                _mm_packus_epi16(packed, packed),
                _mm_cvtsi32_si128(addVal));

            // XOR with buffer
            *(reinterpret_cast<int*>(ptr - 12)) = _mm_cvtsi128_si32(
                _mm_xor_si128(key,
                    _mm_cvtsi32_si128(*(reinterpret_cast<int*>(ptr - 12)))));

            // Second group
            __m128i hi2 = (__m128i)_mm_shuffle_ps(
                (__m128)_mm_mul_epi32(_mm_unpacklo_epi32(idx2, idx2), divisor_magic),
                (__m128)_mm_mul_epi32(_mm_unpackhi_epi32(idx2, idx2), divisor_magic),
                221);
            __m128i q2 = _mm_sra_epi32(_mm_add_epi32(hi2, idx2), shift5);
            q2 = _mm_add_epi32(_mm_srl_epi32(q2, shift31), q2);
            __m128i rem2 = _mm_sub_epi32(idx2, _mm_mullo_epi32(q2, modulus));

            __m128i packed2 = _mm_and_si128(
                _mm_shuffle_epi32(
                    _mm_shufflehi_epi16(
                        _mm_shufflelo_epi16(rem2, 0xD8), 0xD8), 0xD8),
                mask);
            __m128i key2 = _mm_add_epi8(
                _mm_packus_epi16(packed2, packed2),
                _mm_cvtsi32_si128(addVal));

            *(reinterpret_cast<int*>(ptr - 8)) = _mm_cvtsi128_si32(
                _mm_xor_si128(key2,
                    _mm_cvtsi32_si128(*(reinterpret_cast<int*>(ptr - 8)))));
        }
    }

    // Scalar fallback for remaining bytes
    while (i < length)
    {
        buffer[i] ^= static_cast<char>((i % 51) + 52);
        ++i;
    }
}

bool PatchByte(void* address, uint8_t value)
{
    DWORD oldProtect;
    if (!VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    *reinterpret_cast<uint8_t*>(address) = value;

    DWORD temp;
    VirtualProtect(address, 1, oldProtect, &temp);
    return true;
}

// Apply version-specific hooks
// Original: inline code in sub_1800282B0
void ApplyHooks(int engineVersion)
{
    int isaAvailable = Globals::dword_18004F028;
    HMODULE gameModule = GetModuleHandleW(nullptr);

    if (static_cast<unsigned int>(engineVersion - 5914491) <= 0x87618A)
    {
        // Version range: 5914491 - 14801545
        // Decrypt 64-byte pattern and scan
        char pattern1[64];
        memcpy(pattern1, encrypted_pattern_64, 64);
        DecryptPattern(pattern1, 64);

        uintptr_t addr1 = PatternScan::FindPatternRaw(gameModule,
            PatternScan::ParsePattern(pattern1));
        if (!addr1)
        {
            MessageBoxA(nullptr,
                "Rift cannot start due to a pattern mismatch. Please try another version.",
                "Error", MB_ICONERROR);
        }

        // Original: v43 = v40 + 23LL; v44 = (char*)v33 + v43
        __int64 hookTarget = addr1 ? static_cast<__int64>(addr1) + 23 : 0;

        // Decrypt 45-byte pattern
        char pattern2[45];
        memcpy(pattern2, encrypted_pattern_45, 45);
        DecryptPattern(pattern2, 45);

        uintptr_t addr2 = PatternScan::FindPatternRaw(gameModule,
            PatternScan::ParsePattern(pattern2));
        if (!addr2)
        {
            MessageBoxA(nullptr,
                "Rift cannot start due to a pattern mismatch. Please try another version.",
                "Error", MB_ICONERROR);
            addr2 = 0;
        }

        // Byte patches: *(_BYTE*)v44 = 2; v73[6] = 2;
        if (hookTarget)
            *reinterpret_cast<unsigned char*>(hookTarget) = 2;
        if (addr2)
            reinterpret_cast<char*>(addr2)[6] = 2;
    }

    // All versions >= 14801546: decrypt 95-byte and 84-byte patterns
    {
        // Decrypt 95-byte pattern for AdditionalHookFunc
        char pattern95[95];
        memcpy(pattern95, encrypted_pattern_95, 95);
        DecryptPattern(pattern95, 95);

        uintptr_t hookAddr = PatternScan::FindPatternRaw(gameModule,
            PatternScan::ParsePattern(pattern95));
        if (!hookAddr)
        {
            MessageBoxA(nullptr,
                "Rift cannot start due to a pattern mismatch. Please try another version.",
                "Error", MB_ICONERROR);
        }
        Globals::qword_18004FDB8 =
            reinterpret_cast<decltype(Globals::qword_18004FDB8)>(hookAddr);

        // Decrypt 84-byte pattern for AdditionalAddr
        char pattern84[84];
        memcpy(pattern84, encrypted_pattern_84, 84);
        DecryptPattern(pattern84, 84);

        uintptr_t addr84 = PatternScan::FindPatternRaw(gameModule,
            PatternScan::ParsePattern(pattern84));
        if (!addr84)
        {
            MessageBoxA(nullptr,
                "Rift cannot start due to a pattern mismatch. Please try another version.",
                "Error", MB_ICONERROR);
        }
        Globals::qword_18004FDD0 = addr84;
    }
}

} // namespace Hooks
