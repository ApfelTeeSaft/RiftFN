/*
 * Rift DLL - Version Configuration System
 *
 * Original functions:
 *   sub_180001020 - Static initializer that populates the version config tree
 *   sub_180027620 - InitializePatterns (resolves all patterns for current version)
 *   sub_180027260 - PatternLink resolver (searches pattern list by name)
 *   sub_180027090 - PatternEntry constructor
 *
 * The original stores configs in a std::map-like red-black tree (MSVC _Tree)
 * at qword_180050050. Each node is 0x40 bytes containing tree pointers,
 * version range, and a std::vector<PatternEntry> of 5 pattern entries.
 *
 * This file contains all 9 version configurations extracted from the binary.
 * InputKey patterns are stored encrypted and decrypted at runtime.
 */

#include "version_config.h"
#include "pattern_scan.h"
#include <cstring>
#include <cstdlib>

// ============================================================================
// Encrypted InputKey pattern blobs (stored in .rdata in original)
// Decryption: XOR each byte with ((index % 51) + 52)
// The SSE2 vectorized decryption in the original is functionally equivalent.
// ============================================================================

// Blob 1: 87 bytes (configs 1) - from xmmword_180046930..180046970 + "qbctabW"
static const unsigned char g_InputKeyBlob1[87] = {
    0x00, 0x0D, 0x16, 0x0F, 0x7A, 0x19, 0x79, 0x0F,
    0x1C, 0x09, 0x06, 0x1F, 0x78, 0x78, 0x62, 0x76,
    0x7C, 0x65, 0x76, 0x7F, 0x68, 0x7D, 0x72, 0x6B,
    0x74, 0x74, 0x6E, 0x79, 0x68, 0x71, 0x63, 0x63,
    0x74, 0x61, 0x6E, 0x77, 0x60, 0x60, 0x7A, 0x6C,
    0x6C, 0x7D, 0x6F, 0x67, 0x40, 0x55, 0x5A, 0x43,
    0x5C, 0x5C, 0x46, 0x03, 0x0D, 0x16, 0x05, 0x08,
    0x19, 0x0E, 0x0A, 0x1C, 0x08, 0x08, 0x1F, 0x74,
    0x79, 0x62, 0x7B, 0x75, 0x65, 0x03, 0x04, 0x68,
    0x0F, 0x7A, 0x6B, 0x7C, 0x7D, 0x6E, 0x7F, 0x60,
    0x71, 0x62, 0x63, 0x74, 0x61, 0x62, 0x57
};

// Blob 2: 75 bytes (configs 2-6) - from xmmword_1800468B0 + string constants
static const unsigned char g_InputKeyBlob2[75] = {
    0x00, 0x0D, 0x16, 0x0F, 0x7A, 0x19, 0x79, 0x0F,
    0x1C, 0x09, 0x06, 0x1F, 0x78, 0x78, 0x62, 0x76,
    0x7C, 0x65, 0x77, 0x77, 0x68, 0x7D, 0x72, 0x6B,
    0x74, 0x74, 0x6E, 0x78, 0x60, 0x71, 0x63, 0x6B,
    0x74, 0x61, 0x6E, 0x77, 0x60, 0x60, 0x7A, 0x6C,
    0x64, 0x7D, 0x6C, 0x6F, 0x40, 0x55, 0x53, 0x43,
    0x51, 0x53, 0x46, 0x00, 0x0D, 0x16, 0x0F, 0x09,
    0x19, 0x7F, 0x78, 0x1C, 0x7B, 0x0E, 0x1F, 0x70,
    0x71, 0x62, 0x73, 0x74, 0x65, 0x76, 0x77, 0x68,
    0x7D, 0x7E, 0x4B
};

// Blob 3: 82 bytes (config 7) - from xmmword_180046DC0 + mixed constants
static const unsigned char g_InputKeyBlob3[82] = {
    0x00, 0x0D, 0x16, 0x0F, 0x7A, 0x19, 0x79, 0x0F,
    0x1C, 0x09, 0x06, 0x1F, 0x78, 0x78, 0x62, 0x76,
    0x7C, 0x65, 0x77, 0x77, 0x68, 0x7D, 0x72, 0x6B,
    0x74, 0x74, 0x6E, 0x78, 0x68, 0x71, 0x63, 0x6B,
    0x74, 0x60, 0x63, 0x77, 0x6C, 0x68, 0x7A, 0x6E,
    0x6A, 0x7D, 0x6A, 0x6E, 0x40, 0x54, 0x55, 0x43,
    0x50, 0x5D, 0x46, 0x0C, 0x71, 0x16, 0x01, 0x00,
    0x19, 0x05, 0x1B, 0x08, 0x05, 0x1E, 0x07, 0x71,
    0x61, 0x07, 0x00, 0x64, 0x7A, 0x66, 0x78, 0x68,
    0x76, 0x6A, 0x74, 0x6C, 0x79, 0x7A, 0x6F, 0x60,
    0x17, 0x52
};

// Blob 4: 78 bytes (configs 8-9) - from xmmword_1800464D0..180046500 + int constants
static const unsigned char g_InputKeyBlob4[78] = {
    0x00, 0x0D, 0x16, 0x0F, 0x7A, 0x19, 0x79, 0x0F,
    0x1C, 0x09, 0x06, 0x1F, 0x78, 0x78, 0x62, 0x76,
    0x7C, 0x65, 0x77, 0x77, 0x68, 0x7D, 0x72, 0x6B,
    0x74, 0x74, 0x6E, 0x70, 0x70, 0x60, 0x6A, 0x73,
    0x61, 0x60, 0x76, 0x62, 0x6F, 0x79, 0x6E, 0x6A,
    0x7C, 0x68, 0x69, 0x7F, 0x54, 0x59, 0x42, 0x5B,
    0x20, 0x45, 0x50, 0x0C, 0x15, 0x09, 0x17, 0x0C,
    0x01, 0x1A, 0x03, 0x0D, 0x1D, 0x7B, 0x7C, 0x60,
    0x7E, 0x62, 0x7C, 0x64, 0x7A, 0x66, 0x78, 0x68,
    0x7D, 0x7E, 0x6B, 0x7C, 0x0B, 0x4E
};

// Decrypt an encrypted pattern blob in-place: XOR with ((i % 51) + 52)
static std::string DecryptInputKeyBlob(const unsigned char* blob, size_t size)
{
    std::string result(reinterpret_cast<const char*>(blob), size);
    for (size_t i = 0; i < size; i++)
        result[i] ^= static_cast<char>((i % 51) + 52);
    // The decrypted result is a null-terminated pattern string
    return std::string(result.c_str());
}

// ============================================================================
// Pattern string constants (from .rdata section)
// ============================================================================

// GObjects patterns
static const char* PAT_GOBJECTS_V1 =
    "48 8D 05 ? ? ? ? 48 89 01 33 C9 84 D2 41 8B 40 08 "
    "49 89 48 10 0F 45 05 ? ? ? ? FF C0 49 89 48 10 41 89 40 08";

static const char* PAT_GOBJECTS_V2 =
    "48 8D 05 ? ? ? ? 33 F6 48 89 01 48 89 71 10";

static const char* PAT_GOBJECTS_V3 =
    "49 63 C8 48 8D 14 40 48 8B 05 ? ? ? ? 48 8B 0C C8 48 8D 04 D1";

// ProcessEvent patterns
static const char* PAT_PROCESSEVENT_V1 =
    "40 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? "
    "48 8D 6C 24 ? 48 89 9D ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C5 "
    "48 89 85 ? ? ? ? 48 63 41 0C";

static const char* PAT_PROCESSEVENT_V2 =
    "75 ? 4C 8B C6 48 8B D5 48 8B CB E8 ? ? ? ? 48 8B 5C 24";

static const char* PAT_PROCESSEVENT_V3 =
    "40 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? "
    "48 8D 6C 24 ? 48 89 9D ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C5 "
    "48 89 85 ? ? ? ? 8B 41 0C 45 33 F6 3B 05 ? ? ? ? "
    "4D 8B F8 48 8B F2 4C 8B E1 41 B8 ? ? ? ? 7D 2A";

static const char* PAT_PROCESSEVENT_V4 =
    "E8 BF 0B 2A 02 0F B7 1B C1 EB 06 4C 89 36 4C 89 76 08";

// FNameToString pattern (same for all versions)
static const char* PAT_FNAMETOSTRING =
    "C3 48 8B 42 18 48 8D 4C 24 30 48 8B D3 48 89 44 24 30 E8 ? ? ? ?";

// GWorld patterns
static const char* PAT_GWORLD_V1 =
    "48 89 05 ? ? ? ? 48 8B 8F";

static const char* PAT_GWORLD_V2 =
    "48 8B 1D ? ? ? ? 48 85 DB 74 ? 41";

static const char* PAT_GWORLD_V3 =
    "48 89 05 ? ? ? ? 48 8B B3";

static const char* PAT_GWORLD_V4 =
    "48 8B 1D ? ? ? ? 48 85 DB 74 3B 41";

static const char* PAT_GWORLD_V5 =
    "B0 29 D5 AB D6 02 00 00";

// ============================================================================
// Version config storage (equivalent to std::map in original)
// ============================================================================
static std::vector<VersionConfig> g_VersionConfigs;

// ============================================================================
// InitVersionConfigs - equivalent to sub_180001020
// Populates the global version config list with all 9 version ranges.
// Each config maps a Perforce changelist range to a set of 5 patterns:
//   GObjects, ProcessEvent, FNameToString, GWorld, InputKey
// ============================================================================
void VersionManager::InitVersionConfigs()
{
    g_VersionConfigs.clear();
    g_VersionConfigs.reserve(9);

    // Decrypt InputKey blobs
    std::string inputkey1 = DecryptInputKeyBlob(g_InputKeyBlob1, sizeof(g_InputKeyBlob1));
    std::string inputkey2 = DecryptInputKeyBlob(g_InputKeyBlob2, sizeof(g_InputKeyBlob2));
    std::string inputkey3 = DecryptInputKeyBlob(g_InputKeyBlob3, sizeof(g_InputKeyBlob3));
    std::string inputkey4 = DecryptInputKeyBlob(g_InputKeyBlob4, sizeof(g_InputKeyBlob4));

    // Config 1: CL 3700114 - 3785438
    {
        VersionConfig cfg;
        cfg.version_min = 3700114;
        cfg.version_max = 3785438;
        cfg.patterns = {
            {"GObjects",     PAT_GOBJECTS_V1,     3, 0},
            {"ProcessEvent", PAT_PROCESSEVENT_V1,  0, 0},
            {"FNameToString",PAT_FNAMETOSTRING,   19, 0},
            {"GWorld",       PAT_GWORLD_V1,        3, 0},
            {"InputKey",     inputkey1,             0, 0},
        };
        g_VersionConfigs.push_back(std::move(cfg));
    }

    // Config 2: CL 3790078 - 3876086
    {
        VersionConfig cfg;
        cfg.version_min = 3790078;
        cfg.version_max = 3876086;
        cfg.patterns = {
            {"GObjects",     PAT_GOBJECTS_V1,     3, 0},
            {"ProcessEvent", PAT_PROCESSEVENT_V1,  0, 0},
            {"FNameToString",PAT_FNAMETOSTRING,   19, 0},
            {"GWorld",       PAT_GWORLD_V1,        3, 0},
            {"InputKey",     inputkey2,             0, 0},
        };
        g_VersionConfigs.push_back(std::move(cfg));
    }

    // Config 3: CL 3889387 - 4166199
    {
        VersionConfig cfg;
        cfg.version_min = 3889387;
        cfg.version_max = 4166199;
        cfg.patterns = {
            {"GObjects",     PAT_GOBJECTS_V1,     3, 0},
            {"ProcessEvent", PAT_PROCESSEVENT_V1,  0, 0},
            {"FNameToString",PAT_FNAMETOSTRING,   19, 0},
            {"GWorld",       PAT_GWORLD_V1,        3, 0},
            {"InputKey",     inputkey2,             0, 0},
        };
        g_VersionConfigs.push_back(std::move(cfg));
    }

    // Config 4: CL 4204761 - 4461277
    {
        VersionConfig cfg;
        cfg.version_min = 4204761;
        cfg.version_max = 4461277;
        cfg.patterns = {
            {"GObjects",     PAT_GOBJECTS_V2,     3, 0},
            {"ProcessEvent", PAT_PROCESSEVENT_V2, 12, 0},
            {"FNameToString",PAT_FNAMETOSTRING,   19, 0},
            {"GWorld",       PAT_GWORLD_V2,        3, 0},
            {"InputKey",     inputkey2,             0, 0},
        };
        g_VersionConfigs.push_back(std::move(cfg));
    }

    // Config 5: CL 4464155 - 5285981
    {
        VersionConfig cfg;
        cfg.version_min = 4464155;
        cfg.version_max = 5285981;
        cfg.patterns = {
            {"GObjects",     PAT_GOBJECTS_V3,    10, 0},
            {"ProcessEvent", PAT_PROCESSEVENT_V3,  0, 0},
            {"FNameToString",PAT_FNAMETOSTRING,   19, 0},
            {"GWorld",       PAT_GWORLD_V3,        3, 0},
            {"InputKey",     inputkey2,             0, 0},
        };
        g_VersionConfigs.push_back(std::move(cfg));
    }

    // Config 6: CL 5362200 - 11586896
    {
        VersionConfig cfg;
        cfg.version_min = 5362200;
        cfg.version_max = 11586896;
        cfg.patterns = {
            {"GObjects",     PAT_GOBJECTS_V3,    10, 0},
            {"ProcessEvent", PAT_PROCESSEVENT_V3,  0, 0},
            {"FNameToString",PAT_FNAMETOSTRING,   19, 0},
            {"GWorld",       PAT_GWORLD_V4,        3, 0},
            {"InputKey",     inputkey2,             0, 0},
        };
        g_VersionConfigs.push_back(std::move(cfg));
    }

    // Config 7: CL 11794982 - 13498980
    {
        VersionConfig cfg;
        cfg.version_min = 11794982;
        cfg.version_max = 13498980;
        cfg.patterns = {
            {"GObjects",     PAT_GOBJECTS_V3,    10, 0},
            {"ProcessEvent", PAT_PROCESSEVENT_V3,  0, 0},
            {"FNameToString",PAT_FNAMETOSTRING,   19, 0},
            {"GWorld",       PAT_GWORLD_V4,        3, 0},
            {"InputKey",     inputkey3,             0, 0},
        };
        g_VersionConfigs.push_back(std::move(cfg));
    }

    // Config 8: CL 13649278 - 15570449
    {
        VersionConfig cfg;
        cfg.version_min = 13649278;
        cfg.version_max = 15570449;
        cfg.patterns = {
            {"GObjects",     PAT_GOBJECTS_V3,    10, 0},
            {"ProcessEvent", PAT_PROCESSEVENT_V3,  0, 0},
            {"FNameToString",PAT_FNAMETOSTRING,   19, 0},
            {"GWorld",       PAT_GWORLD_V4,        3, 0},
            {"InputKey",     inputkey4,             0, 0},
        };
        g_VersionConfigs.push_back(std::move(cfg));
    }

    // Config 9: CL 15685441 - 15727376
    // Note: different order and different patterns for ProcessEvent and GWorld
    {
        VersionConfig cfg;
        cfg.version_min = 15685441;
        cfg.version_max = 15727376;
        cfg.patterns = {
            {"ProcessEvent", PAT_PROCESSEVENT_V4,  0, 0},
            {"FNameToString",PAT_FNAMETOSTRING,   19, 0},
            {"GWorld",       PAT_GWORLD_V5,        0, 0},
            {"InputKey",     inputkey4,             0, 0},
            {"GObjects",     PAT_GOBJECTS_V3,    10, 0},
        };
        g_VersionConfigs.push_back(std::move(cfg));
    }
}

// ============================================================================
// Helper: find PatternEntry by name in a VersionConfig's pattern list
// Equivalent to sub_180027260 (PatternLink resolver)
// Returns pointer to the matching PatternEntry, or nullptr if not found.
// In the original, failure triggers MessageBoxA("Failed to find PatternLink").
// ============================================================================
static const PatternEntry* FindPatternByName(const VersionConfig& config,
                                              const char* name)
{
    for (const auto& entry : config.patterns)
    {
        if (entry.name == name)
            return &entry;
    }
    MessageBoxA(nullptr, "Failed to find PatternLink", "Error", MB_ICONERROR);
    return nullptr;
}

// ============================================================================
// Helper: scan for pattern and resolve address
// Matches the inline pattern scan + RIP resolution in sub_180027620
// ============================================================================
static __int64 ScanAndResolve(HMODULE module, const PatternEntry* entry)
{
    if (!entry)
        return 0;

    auto pattern = PatternScan::ParsePattern(entry->pattern.c_str());
    uintptr_t addr = PatternScan::FindPatternRaw(module, pattern);

    if (!addr)
    {
        MessageBoxA(nullptr,
            "Rift cannot start due to a pattern mismatch. Please try another version.",
            "Error", MB_ICONERROR);
        return 0;
    }

    __int64 result = static_cast<__int64>(addr);

    // Apply RIP-relative resolution
    if (entry->offset_a)
        result = result + entry->offset_a +
                 *reinterpret_cast<int*>(result + entry->offset_a) + 4;

    // Apply additional offset
    if (entry->offset_b)
        result += entry->offset_b;

    return result;
}

// ============================================================================
// InitializePatterns - Original: sub_180027620
//
// Finds the matching version config, resolves all 5 patterns, stores
// resolved addresses in globals, then performs version-specific GObjects
// adjustments to create PatternLink structures.
// ============================================================================
int VersionManager::InitializePatterns()
{
    int v0 = Globals::dword_18004FDE0;

    if (!v0)
    {
        MessageBoxA(nullptr, "EngineVersion is NULL", "Error", MB_ICONERROR);
        v0 = Globals::dword_18004FDE0;
    }

    // Find matching version config
    const VersionConfig* config = nullptr;
    for (const auto& cfg : g_VersionConfigs)
    {
        if (v0 >= cfg.version_min && v0 <= cfg.version_max)
        {
            config = &cfg;
            break;
        }
    }

    if (!config)
    {
        return (int)(intptr_t)MessageBoxA(nullptr, "Unsupported version!",
                                          "Error", MB_ICONERROR);
    }

    // Resolve all 5 patterns
    const PatternEntry* gobjects_entry = FindPatternByName(*config, "GObjects");
    const PatternEntry* pe_entry = FindPatternByName(*config, "ProcessEvent");
    const PatternEntry* fnts_entry = FindPatternByName(*config, "FNameToString");
    const PatternEntry* gw_entry = FindPatternByName(*config, "GWorld");
    const PatternEntry* ik_entry = FindPatternByName(*config, "InputKey");

    HMODULE gameModule = GetModuleHandleW(nullptr);

    // Resolve GObjects
    __int64 gobjects = ScanAndResolve(gameModule, gobjects_entry);
    Globals::qword_18004FDD8 = gobjects;

    // Resolve ProcessEvent
    __int64 processEvent = ScanAndResolve(gameModule, pe_entry);
    Globals::qword_18004FDE8 = reinterpret_cast<decltype(Globals::qword_18004FDE8)>(processEvent);

    // Resolve FNameToString
    __int64 fnameToString = ScanAndResolve(gameModule, fnts_entry);
    Globals::qword_18004FDC8 = fnameToString;

    // Resolve GWorld
    __int64 gworld = ScanAndResolve(gameModule, gw_entry);
    Globals::qword_18004FDB0 = gworld;

    // Resolve InputKey
    __int64 inputkey = ScanAndResolve(gameModule, ik_entry);
    Globals::qword_18004FDA8 = inputkey;

    // Validate all critical addresses
    __int64 v89 = Globals::qword_18004FDD8;
    if (!Globals::qword_18004FDD8)
    {
        MessageBoxA(nullptr, "An error has occured.", "Error", MB_ICONERROR);
        v89 = Globals::qword_18004FDD8;
    }
    if (!Globals::qword_18004FDE8)
    {
        MessageBoxA(nullptr, "An error has occured.", "Error", MB_ICONERROR);
        v89 = Globals::qword_18004FDD8;
    }
    if (!Globals::qword_18004FDC8)
    {
        MessageBoxA(nullptr, "An error has occured.", "Error", MB_ICONERROR);
        v89 = Globals::qword_18004FDD8;
    }
    if (!Globals::qword_18004FDB0)
    {
        MessageBoxA(nullptr, "An error has occured.", "Error", MB_ICONERROR);
        v89 = Globals::qword_18004FDD8;
    }
    if (!Globals::qword_18004FDA8)
    {
        MessageBoxA(nullptr, "An error has occured.", "Error", MB_ICONERROR);
        v89 = Globals::qword_18004FDD8;
    }

    // ========================================================================
    // Version-specific GObjects adjustment and PatternLink creation
    // This section adjusts the GObjects address based on version range,
    // scanning forward from the resolved address to find a wildcard boundary.
    // ========================================================================
    int engineVer = Globals::dword_18004FDE0;

    if (static_cast<unsigned int>(engineVer - 4204761) <= 0x2679)
    {
        // Version range: 4204761 - 4214617 (exactly matches (unsigned)(v-4204761) <= 0x2679)
        // Scan forward from GObjects+2, looking for 4 consecutive -1 (wildcard) int32s
        char* scan = reinterpret_cast<char*>(v89 + 2);
        char* found = nullptr;
        __int64 limit = -2 - v89;
        do
        {
            found = scan - 2;
            if (*reinterpret_cast<int*>(scan - 2) == -1) break;
            found = scan - 1;
            if (*reinterpret_cast<int*>(scan - 1) == -1) break;
            found = scan;
            if (*reinterpret_cast<int*>(scan) == -1) break;
            found = scan + 1;
            if (*reinterpret_cast<int*>(scan + 1) == -1) break;
            scan += 4;
        } while (reinterpret_cast<__int64>(&scan[limit]) < 2048);

        Globals::qword_18004FDD8 = reinterpret_cast<__int64>(found - 24);

        // Create PatternLink structure (0x10 bytes)
        auto* plink = reinterpret_cast<__int64*>(operator new(0x10));
        *reinterpret_cast<unsigned __int128*>(plink) = 0;
        *reinterpret_cast<unsigned char*>(plink) = 1;
        plink[1] = Globals::qword_18004FDD8;
        Globals::qword_18004FDF0 = reinterpret_cast<__int64>(plink);
    }
    else if (static_cast<unsigned int>(engineVer - 4225813) <= 0x397C8)
    {
        // Version range: 4225813 - 4461513
        char* scan = reinterpret_cast<char*>(v89 + 2);
        char* found = nullptr;
        __int64 limit = -2 - v89;
        do
        {
            found = scan - 2;
            if (*reinterpret_cast<int*>(scan - 2) == -1) break;
            found = scan - 1;
            if (*reinterpret_cast<int*>(scan - 1) == -1) break;
            found = scan;
            if (*reinterpret_cast<int*>(scan) == -1) break;
            found = scan + 1;
            if (*reinterpret_cast<int*>(scan + 1) == -1) break;
            scan += 4;
        } while (reinterpret_cast<__int64>(&scan[limit]) < 2048);

        Globals::qword_18004FDD8 = reinterpret_cast<__int64>(found - 32);

        auto* plink = reinterpret_cast<__int64*>(operator new(0x10));
        *reinterpret_cast<unsigned __int128*>(plink) = 0;
        *reinterpret_cast<unsigned char*>(plink) = 2;
        plink[1] = Globals::qword_18004FDD8;
        Globals::qword_18004FDF0 = reinterpret_cast<__int64>(plink);
    }
    else if (engineVer < 4464155)
    {
        // Versions between 4461514 and 4464154
        char* scan = reinterpret_cast<char*>(v89 + 2);
        char* found = nullptr;
        __int64 limit = -2 - v89;
        do
        {
            found = scan - 2;
            if (*reinterpret_cast<int*>(scan - 2) == -1) break;
            found = scan - 1;
            if (*reinterpret_cast<int*>(scan - 1) == -1) break;
            found = scan;
            if (*reinterpret_cast<int*>(scan) == -1) break;
            found = scan + 1;
            if (*reinterpret_cast<int*>(scan + 1) == -1) break;
            scan += 4;
        } while (reinterpret_cast<__int64>(&scan[limit]) < 2048);

        Globals::qword_18004FDD8 = reinterpret_cast<__int64>(found - 16);

        auto* plink = reinterpret_cast<__int64*>(operator new(0x10));
        *reinterpret_cast<unsigned __int128*>(plink) = 0;
        *reinterpret_cast<unsigned char*>(plink) = 2;
        plink[1] = Globals::qword_18004FDD8;
        Globals::qword_18004FDF0 = reinterpret_cast<__int64>(plink);
    }
    // else: versions >= 4464155 don't need GObjects adjustment

    if (!Globals::qword_18004FDF0)
        MessageBoxA(nullptr, "An error has occured.", "Error", MB_ICONERROR);

    return static_cast<int>(Globals::qword_18004FDD8);
}
