#pragma once

#include "globals.h"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace Config {
    struct RiftConfig {
        std::vector<std::string> enabledMods;
        std::map<std::string, std::string> streamMap;
    };

    // Load configuration from JSON file
    bool LoadConfig(const std::string& path, RiftConfig& config);

    // Get temp directory path for config storage
    std::string GetConfigPath();
}
