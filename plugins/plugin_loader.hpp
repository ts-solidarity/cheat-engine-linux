#pragma once
/// Plugin system — loads .so plugins from a directory.

#include <string>
#include <vector>
#include <filesystem>

namespace ce {

struct PluginInfo {
    std::string name;
    std::string path;
    std::string version;
    void* handle = nullptr; // dlopen handle
};

class PluginLoader {
public:
    /// Load all .so plugins from a directory.
    void loadDirectory(const std::filesystem::path& dir);

    /// Load a single plugin.
    bool loadPlugin(const std::filesystem::path& path);

    /// Unload all plugins.
    void unloadAll();

    const std::vector<PluginInfo>& plugins() const { return plugins_; }

    ~PluginLoader() { unloadAll(); }

private:
    std::vector<PluginInfo> plugins_;
};

} // namespace ce
