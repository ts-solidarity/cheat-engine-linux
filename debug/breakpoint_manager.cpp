#include "debug/breakpoint_manager.hpp"
#include <algorithm>

namespace ce {

int BreakpointManager::add(const Breakpoint& bp) {
    std::lock_guard lock(mutex_);
    Breakpoint b = bp;
    b.id = nextId_++;
    if (b.hwRegister < 0)
        b.hwRegister = findFreeHwRegister();
    breakpoints_.push_back(b);
    return b.id;
}

void BreakpointManager::remove(int id) {
    std::lock_guard lock(mutex_);
    breakpoints_.erase(
        std::remove_if(breakpoints_.begin(), breakpoints_.end(),
            [id](const Breakpoint& b) { return b.id == id; }),
        breakpoints_.end());
    hitLog_.erase(id);
}

void BreakpointManager::setEnabled(int id, bool enabled) {
    std::lock_guard lock(mutex_);
    for (auto& b : breakpoints_)
        if (b.id == id) { b.enabled = enabled; break; }
}

std::vector<Breakpoint> BreakpointManager::list() const {
    std::lock_guard lock(mutex_);
    return breakpoints_;
}

const Breakpoint* BreakpointManager::get(int id) const {
    std::lock_guard lock(mutex_);
    for (auto& b : breakpoints_)
        if (b.id == id) return &b;
    return nullptr;
}

int BreakpointManager::findFreeHwRegister() const {
    bool used[4] = {};
    for (auto& b : breakpoints_)
        if (b.enabled && b.hwRegister >= 0 && b.hwRegister < 4)
            used[b.hwRegister] = true;
    for (int i = 0; i < 4; ++i)
        if (!used[i]) return i;
    return -1; // All in use
}

bool BreakpointManager::applyToThread(Debugger& dbg, pid_t tid) {
    std::lock_guard lock(mutex_);
    for (auto& bp : breakpoints_) {
        if (!bp.enabled || bp.hwRegister < 0) continue;
        if (bp.threadFilter != 0 && bp.threadFilter != tid) continue;

        int hwType = 0;
        switch (bp.type) {
            case BpType::Execute: hwType = 0; break;
            case BpType::Write:   hwType = 1; break;
            case BpType::Read:    hwType = 3; break; // x86: 3 = read/write
            case BpType::Access:  hwType = 3; break;
        }

        int hwSize = 0;
        switch (bp.size) {
            case 1: hwSize = 0; break;
            case 2: hwSize = 1; break;
            case 4: hwSize = 3; break;
            case 8: hwSize = 2; break; // x86 encoding: 2 = 8 bytes
        }

        auto r = dbg.setBreakpoint(tid, bp.hwRegister, bp.address, hwType, hwSize);
        if (!r) return false;
    }
    return true;
}

bool BreakpointManager::removeFromThread(Debugger& dbg, pid_t tid) {
    std::lock_guard lock(mutex_);
    for (auto& bp : breakpoints_) {
        if (bp.hwRegister >= 0)
            dbg.removeBreakpoint(tid, bp.hwRegister);
    }
    return true;
}

void BreakpointManager::recordHit(int id, const BreakpointHit& hit) {
    std::lock_guard lock(mutex_);

    for (auto& bp : breakpoints_) {
        if (bp.id == id) {
            bp.hitCount++;
            if (bp.oneShot) bp.enabled = false;
            break;
        }
    }

    hitLog_[id].push_back(hit);

    // Cap log at 10000 entries per breakpoint
    if (hitLog_[id].size() > 10000)
        hitLog_[id].erase(hitLog_[id].begin(), hitLog_[id].begin() + 5000);

    if (hitCallback_) {
        auto* bp = get(id);
        if (bp) hitCallback_(*bp, hit);
    }
}

std::vector<BreakpointHit> BreakpointManager::getHits(int id) const {
    std::lock_guard lock(mutex_);
    auto it = hitLog_.find(id);
    return it != hitLog_.end() ? it->second : std::vector<BreakpointHit>{};
}

void BreakpointManager::clearHits(int id) {
    std::lock_guard lock(mutex_);
    hitLog_.erase(id);
}

} // namespace ce
