#pragma once
/// Managed runtime detection helpers for Mono and CoreCLR targets.

#include "platform/process_api.hpp"

#include <string>
#include <vector>

namespace ce {

enum class ManagedRuntimeKind {
    Mono,
    CoreCLR,
};

struct ManagedRuntimeInfo {
    ManagedRuntimeKind kind;
    std::string name;
    std::string moduleName;
    std::string modulePath;
    uintptr_t base = 0;
    size_t size = 0;
};

std::vector<ManagedRuntimeInfo> detectManagedRuntimes(ProcessHandle& proc);

} // namespace ce
