#include "analysis/managed_runtime.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
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

bool isRuntimeModuleName(const std::string& text, ManagedRuntimeKind kind) {
    if (kind == ManagedRuntimeKind::Mono) {
        return containsAny(text, {
            "libmonosgen", "libmono-2.0", "libmono", "/mono/", "mono-sgen"
        });
    }
    return containsAny(text, {
        "libcoreclr.so", "coreclr.dll", "libclrjit.so", "clrjit.dll",
        "libhostpolicy.so", "system.private.corelib"
    });
}

bool rangeContains(const MemoryRegion& range, uintptr_t address) {
    auto end = range.base + range.size;
    return address >= range.base && address < end && end >= range.base;
}

uintptr_t readPointer(const uint8_t* data, size_t pointerSize) {
    if (pointerSize == 4) {
        uint32_t value = 0;
        std::memcpy(&value, data, sizeof(value));
        return value;
    }

    uint64_t value = 0;
    std::memcpy(&value, data, sizeof(value));
    return static_cast<uintptr_t>(value);
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

std::vector<ManagedObjectInfo> enumerateManagedObjects(
    ProcessHandle& proc,
    const ManagedObjectEnumerationConfig& config) {
    auto pointerSize = config.pointerSize != 0 ? config.pointerSize : (proc.is64bit() ? 8 : 4);
    if (pointerSize != 4 && pointerSize != 8)
        return {};

    std::vector<MemoryRegion> typeRanges = config.typeHandleRanges;
    if (typeRanges.empty()) {
        for (const auto& module : proc.modules()) {
            auto haystack = lowerCopy(module.name + "\n" + module.path);
            if ((config.runtimeKind && isRuntimeModuleName(haystack, *config.runtimeKind)) ||
                (!config.runtimeKind && (isRuntimeModuleName(haystack, ManagedRuntimeKind::Mono) ||
                    isRuntimeModuleName(haystack, ManagedRuntimeKind::CoreCLR)))) {
                typeRanges.push_back({
                    module.base,
                    module.size,
                    MemProt::Read,
                    MemType::Image,
                    MemState::Committed,
                    module.path,
                });
            }
        }
    }
    if (typeRanges.empty())
        return {};

    std::vector<ManagedObjectInfo> objects;
    std::vector<uint8_t> buffer;

    for (const auto& region : proc.queryRegions()) {
        if (objects.size() >= config.maxObjects)
            break;
        if (region.state != MemState::Committed || !(region.protection & MemProt::Read))
            continue;
        if (config.writableRegionsOnly && !(region.protection & MemProt::Write))
            continue;
        if (region.protection & MemProt::Exec)
            continue;
        if (config.heapEnd != 0 && region.base >= config.heapEnd)
            continue;
        auto regionEnd = region.base + region.size;
        if (config.heapStart != 0 && regionEnd <= config.heapStart)
            continue;

        auto scanStart = std::max(region.base, config.heapStart);
        auto scanEnd = config.heapEnd == 0 ? regionEnd : std::min(regionEnd, config.heapEnd);
        if (scanEnd <= scanStart || scanEnd - scanStart < pointerSize)
            continue;

        auto size = scanEnd - scanStart;
        buffer.resize(size);
        auto read = proc.read(scanStart, buffer.data(), size);
        if (!read || *read < pointerSize)
            continue;

        auto readable = *read;
        for (size_t offset = 0; offset + pointerSize <= readable; offset += pointerSize) {
            auto typeHandle = readPointer(buffer.data() + offset, pointerSize);
            if (typeHandle == 0)
                continue;

            auto typeRange = std::find_if(typeRanges.begin(), typeRanges.end(), [&](const MemoryRegion& range) {
                return rangeContains(range, typeHandle);
            });
            if (typeRange == typeRanges.end())
                continue;

            objects.push_back({
                scanStart + offset,
                typeHandle,
                0,
                config.runtimeKind,
                region.path,
            });
            if (objects.size() >= config.maxObjects)
                break;
        }
    }

    return objects;
}

} // namespace ce
