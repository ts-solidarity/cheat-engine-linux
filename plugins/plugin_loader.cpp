#include "plugins/plugin_loader.hpp"
#include <dlfcn.h>
#include <cstdio>

namespace ce {

// Expected plugin exports:
// const char* ce_plugin_name();
// const char* ce_plugin_version();
// int ce_plugin_init();
// void ce_plugin_cleanup();

void PluginLoader::loadDirectory(const std::filesystem::path& dir) {
    if (!std::filesystem::exists(dir)) return;

    for (auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.path().extension() == ".so")
            loadPlugin(entry.path());
    }
}

bool PluginLoader::loadPlugin(const std::filesystem::path& path) {
    void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "Plugin load failed: %s: %s\n", path.c_str(), dlerror());
        return false;
    }

    PluginInfo info;
    info.path = path.string();
    info.handle = handle;

    // Get plugin name
    auto getName = (const char*(*)())dlsym(handle, "ce_plugin_name");
    info.name = getName ? getName() : path.stem().string();

    auto getVersion = (const char*(*)())dlsym(handle, "ce_plugin_version");
    info.version = getVersion ? getVersion() : "unknown";

    // Call init
    auto init = (int(*)())dlsym(handle, "ce_plugin_init");
    if (init && init() != 0) {
        fprintf(stderr, "Plugin init failed: %s\n", info.name.c_str());
        dlclose(handle);
        return false;
    }

    plugins_.push_back(std::move(info));
    return true;
}

void PluginLoader::unloadAll() {
    for (auto& p : plugins_) {
        if (p.handle) {
            auto cleanup = (void(*)())dlsym(p.handle, "ce_plugin_cleanup");
            if (cleanup) cleanup();
            dlclose(p.handle);
        }
    }
    plugins_.clear();
}

} // namespace ce
