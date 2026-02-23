#pragma once

#include "globals.h"
#include <string>
#include <vector>

// PatternEntry: 72 bytes in original binary
// Layout: name (std::string, 32 bytes) + pattern (std::string, 32 bytes) + offset_a (int, 4) + offset_b (int, 4)
struct PatternEntry {
    std::string name;      // offset 0: pattern identifier (e.g., "GObjects")
    std::string pattern;   // offset 32: IDA-style hex pattern string
    int offset_a;          // offset 64: RIP-relative displacement offset (0 = no resolution)
    int offset_b;          // offset 68: additional offset adjustment
};

// VersionConfig: stored as value in std::map keyed by version_min
// Original tree node is 0x40 bytes: tree pointers (24) + color/nil flags (8) + data (32)
// Data portion: version_min (int) + version_max (int) + pattern_list (std::vector<PatternEntry>)
struct VersionConfig {
    int version_min;
    int version_max;
    std::vector<PatternEntry> patterns;
};

namespace VersionManager {
    // Initialize the version config tree (sub_180001020 equivalent)
    // Populates the global tree at qword_180050050 with all 9 version configs
    void InitVersionConfigs();

    // Resolve all patterns for the current engine version
    // Original: sub_180027620
    int InitializePatterns();
}
