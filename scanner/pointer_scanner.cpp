#include "scanner/pointer_scanner.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <queue>
#include <set>

namespace ce {

std::string PointerPath::toString() const {
    std::string result;
    // Build from inside out: [[module+base]+off1]+off2
    for (int i = (int)offsets.size() - 1; i >= 0; --i)
        result += "[";

    char buf[64];
    snprintf(buf, sizeof(buf), "%s+%lx", module.c_str(), baseOffset);
    result += buf;

    for (auto off : offsets) {
        result += "]";
        if (off >= 0)
            snprintf(buf, sizeof(buf), "+0x%x", off);
        else
            snprintf(buf, sizeof(buf), "-0x%x", -off);
        result += buf;
    }
    return result;
}

// ── Reverse pointer map ──
// Maps: pointed_to_address → vector of (address_containing_pointer)
// We use a sorted vector for cache-friendly binary search.

struct PointerEntry {
    uintptr_t pointsTo;     // The value (pointer target)
    uintptr_t locatedAt;    // Address containing this pointer
};

struct StaticInfo {
    uintptr_t base;
    std::string module;
};

static bool isInRange(uintptr_t addr, const std::vector<MemoryRegion>& regions) {
    for (auto& r : regions)
        if (addr >= r.base && addr < r.base + r.size)
            return true;
    return false;
}

std::vector<PointerPath> PointerScanner::scan(ProcessHandle& proc, const PointerScanConfig& config) {
    cancelled_.store(false);
    progress_.store(0);

    auto regions = proc.queryRegions();
    auto modules = proc.modules();

    // Build quick lookup: is address in a module? (static pointer)
    auto findModule = [&](uintptr_t addr) -> const ModuleInfo* {
        for (auto& m : modules)
            if (addr >= m.base && addr < m.base + m.size)
                return &m;
        return nullptr;
    };

    // ── Phase 1: Build reverse pointer map ──
    // Read all memory and find pointer-like values

    std::vector<PointerEntry> entries;
    entries.reserve(1024 * 1024); // Preallocate ~16MB

    size_t totalMem = 0;
    for (auto& r : regions) totalMem += r.size;

    size_t scanned = 0;
    std::vector<uint8_t> buf;

    for (auto& region : regions) {
        if (cancelled_.load()) break;
        if (!(region.protection & MemProt::Read)) continue;

        buf.resize(region.size);
        auto rr = proc.read(region.base, buf.data(), region.size);
        if (!rr || *rr < 8) { scanned += region.size; continue; }
        size_t bytesRead = *rr;

        size_t step = config.alignedOnly ? 8 : 1;
        size_t limit = bytesRead - 7;

        for (size_t offset = 0; offset < limit; offset += step) {
            uintptr_t val;
            std::memcpy(&val, buf.data() + offset, 8);

            // Check if this looks like a valid pointer (points into mapped memory)
            if (val < 0x10000 || val > 0x7fffffffffff) continue;
            if (!isInRange(val, regions)) continue;

            entries.push_back({val, region.base + offset});
        }

        scanned += region.size;
        progress_.store(0.5f * scanned / totalMem); // Phase 1 = 0-50%
    }

    if (cancelled_.load()) return {};

    // Sort by pointsTo for fast range queries
    std::sort(entries.begin(), entries.end(),
        [](const PointerEntry& a, const PointerEntry& b) { return a.pointsTo < b.pointsTo; });

    // ── Phase 2: Reverse BFS from target ──

    struct WorkItem {
        uintptr_t address;          // Address to find pointers TO
        std::vector<int32_t> offsets; // Offsets collected so far
        int depth;
    };

    std::vector<PointerPath> results;
    std::queue<WorkItem> queue;
    std::set<uintptr_t> visited; // Prevent cycles

    queue.push({config.targetAddress, {}, 0});
    visited.insert(config.targetAddress);

    size_t totalWork = 1;
    size_t doneWork = 0;

    while (!queue.empty() && !cancelled_.load()) {
        auto item = queue.front();
        queue.pop();
        ++doneWork;

        if (item.depth > 0)
            progress_.store(0.5f + 0.5f * doneWork / std::max(totalWork, size_t(1)));

        // Search window: find all pointers that point to [address - maxOffset, address + (negativeOffsets ? maxOffset : 0)]
        uintptr_t searchMin = (item.address > (uintptr_t)config.maxOffset) ?
            item.address - config.maxOffset : 0;
        uintptr_t searchMax = item.address;
        if (config.negativeOffsets)
            searchMax = item.address + config.maxOffset;

        // Binary search for range [searchMin, searchMax] in sorted entries
        auto lo = std::lower_bound(entries.begin(), entries.end(), searchMin,
            [](const PointerEntry& e, uintptr_t val) { return e.pointsTo < val; });
        auto hi = std::upper_bound(entries.begin(), entries.end(), searchMax,
            [](uintptr_t val, const PointerEntry& e) { return val < e.pointsTo; });

        for (auto it = lo; it != hi && !cancelled_.load(); ++it) {
            int32_t offset = (int32_t)(item.address - it->pointsTo);

            // Build new offset chain
            auto newOffsets = item.offsets;
            newOffsets.insert(newOffsets.begin(), offset); // Prepend (innermost first)

            // Check if this pointer is in a static module
            auto* mod = findModule(it->locatedAt);
            if (mod) {
                // Found a static path!
                PointerPath path;
                path.module = mod->name;
                path.moduleBase = mod->base;
                path.baseOffset = it->locatedAt - mod->base;
                path.offsets = newOffsets;
                results.push_back(std::move(path));

                // Cap results
                if (results.size() >= 10000) goto done;
            }

            // Go deeper if not at max depth and not static-only
            if (item.depth + 1 < config.maxDepth) {
                if (!visited.count(it->locatedAt)) {
                    visited.insert(it->locatedAt);
                    queue.push({it->locatedAt, newOffsets, item.depth + 1});
                    ++totalWork;
                }
            }
        }
    }

done:
    progress_.store(1.0f);
    return results;
}

uintptr_t PointerScanner::dereference(ProcessHandle& proc, const PointerPath& path) {
    // Find module base
    auto modules = proc.modules();
    uintptr_t base = 0;
    for (auto& m : modules) {
        if (m.name == path.module) { base = m.base; break; }
    }
    if (base == 0) return 0;

    uintptr_t addr = base + path.baseOffset;

    for (auto off : path.offsets) {
        uintptr_t ptr = 0;
        auto r = proc.read(addr, &ptr, sizeof(ptr));
        if (!r || *r < sizeof(ptr) || ptr == 0) return 0;
        addr = ptr + off;
    }

    return addr;
}

} // namespace ce
