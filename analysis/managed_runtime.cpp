#include "analysis/managed_runtime.hpp"

#include <algorithm>
#include <cctype>
#include <initializer_list>

namespace ce {
namespace {

std::string lowerCopy(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

bool containsAny(const std::string& text, std::initializer_list<const char*> needles) {
    for (const auto* needle : needles) {
        if (text.find(needle) != std::string::npos)
            return true;
    }
    return false;
}

} // namespace

std::vector<ManagedRuntimeInfo> detectManagedRuntimes(ProcessHandle& proc) {
    std::vector<ManagedRuntimeInfo> runtimes;
    bool sawMono = false;
    bool sawCoreClr = false;

    for (const auto& module : proc.modules()) {
        auto name = lowerCopy(module.name);
        auto path = lowerCopy(module.path);
        auto haystack = name + "\n" + path;

        if (!sawMono && containsAny(haystack, {
            "libmonosgen", "libmono-2.0", "libmono", "/mono/", "mono-sgen"
        })) {
            runtimes.push_back({
                ManagedRuntimeKind::Mono,
                "Mono",
                module.name,
                module.path,
                module.base,
                module.size,
            });
            sawMono = true;
            continue;
        }

        if (!sawCoreClr && containsAny(haystack, {
            "libcoreclr.so", "coreclr.dll", "libclrjit.so", "clrjit.dll",
            "libhostpolicy.so", "system.private.corelib"
        })) {
            runtimes.push_back({
                ManagedRuntimeKind::CoreCLR,
                "CoreCLR",
                module.name,
                module.path,
                module.base,
                module.size,
            });
            sawCoreClr = true;
        }
    }

    return runtimes;
}

} // namespace ce
