#pragma once
/// Pointer scanner — finds stable pointer chains to dynamic addresses.

#include "platform/process_api.hpp"
#include <vector>
#include <string>
#include <atomic>
#include <cstddef>

namespace ce {

/// A pointer path: module+baseOffset → [offset1] → [offset2] → ... → target
struct PointerPath {
    std::string module;         // Module name (e.g., "game")
    uintptr_t   moduleBase;     // Module base address (for display)
    uintptr_t   baseOffset;     // Offset from module base
    std::vector<int32_t> offsets; // Dereference offsets at each level

    /// Human-readable string: [[game.exe+0x100]+0x20]+0x8
    std::string toString() const;
};

struct PointerScanConfig {
    uintptr_t targetAddress = 0;
    int       maxDepth = 4;         // Max levels of indirection (2-7)
    int       maxOffset = 2048;     // Max offset from pointer to target
    bool      negativeOffsets = false;
    bool      alignedOnly = true;   // 8-byte aligned pointers only
    bool      staticOnly = true;    // Only save paths ending at static (module) addresses
    size_t    shardIndex = 0;       // Worker shard for distributed scans
    size_t    shardCount = 1;       // Total distributed workers
};

/// Build one config per worker. Merged results are equivalent to a full scan.
std::vector<PointerScanConfig> makePointerScanShards(const PointerScanConfig& base, size_t shardCount);

class PointerScanner {
public:
    PointerScanner() = default;

    /// Run a pointer scan. Returns all found paths.
    std::vector<PointerPath> scan(ProcessHandle& proc, const PointerScanConfig& config);

    /// Dereference a pointer path in the target process.
    /// Returns the final address, or 0 if any dereference fails.
    static uintptr_t dereference(ProcessHandle& proc, const PointerPath& path);

    /// Progress (0.0 - 1.0)
    float progress() const { return progress_.load(std::memory_order_relaxed); }

    void cancel() { cancelled_.store(true); }

private:
    std::atomic<float> progress_{0};
    std::atomic<bool> cancelled_{false};
};

} // namespace ce
