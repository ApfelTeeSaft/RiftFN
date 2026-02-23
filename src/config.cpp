/*
 * Rift DLL - Configuration System
 *
 * Loads JSON configuration files for mod settings.
 * Uses nlohmann::json v3.10.2 for parsing.
 */

#include "config.h"
#include <filesystem>

namespace fs = std::filesystem;

namespace Config {

bool LoadConfig(const std::string& path, RiftConfig& config)
{
    try {
        std::ifstream file(path);
        if (!file.is_open()) {
            MessageBoxA(nullptr,
                (std::string("Failed to get configuration from path ") + path).c_str(),
                "Error", MB_ICONERROR);
            return false;
        }

        nlohmann::json j;
        file >> j;

        if (j.contains("enabledMods")) {
            config.enabledMods = j["enabledMods"].get<std::vector<std::string>>();
        }

        if (j.contains("streamMap")) {
            config.streamMap = j["streamMap"].get<std::map<std::string, std::string>>();
        }

        return true;
    }
    catch (const nlohmann::json::exception& e) {
        MessageBoxA(nullptr, e.what(), "Error", MB_ICONERROR);
        return false;
    }
}

std::string GetConfigPath()
{
    try {
        auto tempPath = fs::temp_directory_path();
        // TODO: Reconstruct exact config path logic
        return tempPath.string();
    }
    catch (const fs::filesystem_error&) {
        return "";
    }
}

} // namespace Config
