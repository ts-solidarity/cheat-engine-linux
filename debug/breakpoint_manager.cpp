#include "debug/breakpoint_manager.hpp"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include <algorithm>
#include <cstdio>
#include <memory>

namespace ce {
namespace {

struct LuaStateDeleter {
    void operator()(lua_State* L) const {
        if (L) lua_close(L);
    }
};

void setGlobalInteger(lua_State* L, const char* name, uint64_t value) {
    lua_pushinteger(L, static_cast<lua_Integer>(value));
    lua_setglobal(L, name);
}

void setRegister(lua_State* L, const char* lower, const char* upper, uint64_t value) {
    setGlobalInteger(L, lower, value);
    setGlobalInteger(L, upper, value);
}

void setTableInteger(lua_State* L, const char* name, uint64_t value) {
    lua_pushinteger(L, static_cast<lua_Integer>(value));
    lua_setfield(L, -2, name);
}

void setTableString(lua_State* L, const char* name, const std::string& value) {
    lua_pushlstring(L, value.data(), value.size());
    lua_setfield(L, -2, name);
}

void exposeConditionGlobals(lua_State* L, const Breakpoint& bp, const BreakpointHit& hit) {
    const auto& ctx = hit.context;
    const auto nextHitCount = static_cast<uint64_t>(bp.hitCount + 1);

    setGlobalInteger(L, "bpId", bp.id);
    setGlobalInteger(L, "address", hit.address);
    setGlobalInteger(L, "rip", hit.rip);
    setGlobalInteger(L, "tid", static_cast<uint64_t>(hit.tid));
    setGlobalInteger(L, "hitCount", nextHitCount);

    setRegister(L, "rax", "RAX", ctx.rax);
    setRegister(L, "rbx", "RBX", ctx.rbx);
    setRegister(L, "rcx", "RCX", ctx.rcx);
    setRegister(L, "rdx", "RDX", ctx.rdx);
    setRegister(L, "rsi", "RSI", ctx.rsi);
    setRegister(L, "rdi", "RDI", ctx.rdi);
    setRegister(L, "rbp", "RBP", ctx.rbp);
    setRegister(L, "rsp", "RSP", ctx.rsp);
    setRegister(L, "r8",  "R8",  ctx.r8);
    setRegister(L, "r9",  "R9",  ctx.r9);
    setRegister(L, "r10", "R10", ctx.r10);
    setRegister(L, "r11", "R11", ctx.r11);
    setRegister(L, "r12", "R12", ctx.r12);
    setRegister(L, "r13", "R13", ctx.r13);
    setRegister(L, "r14", "R14", ctx.r14);
    setRegister(L, "r15", "R15", ctx.r15);
    setRegister(L, "rflags", "RFLAGS", ctx.rflags);

    lua_newtable(L);
    setTableInteger(L, "id", bp.id);
    setTableInteger(L, "address", bp.address);
    setTableInteger(L, "hitCount", nextHitCount);
    setTableString(L, "description", bp.description);
    lua_setglobal(L, "bp");

    lua_newtable(L);
    setTableInteger(L, "rax", ctx.rax);
    setTableInteger(L, "rbx", ctx.rbx);
    setTableInteger(L, "rcx", ctx.rcx);
    setTableInteger(L, "rdx", ctx.rdx);
    setTableInteger(L, "rsi", ctx.rsi);
    setTableInteger(L, "rdi", ctx.rdi);
    setTableInteger(L, "rbp", ctx.rbp);
    setTableInteger(L, "rsp", ctx.rsp);
    setTableInteger(L, "r8", ctx.r8);
    setTableInteger(L, "r9", ctx.r9);
    setTableInteger(L, "r10", ctx.r10);
    setTableInteger(L, "r11", ctx.r11);
    setTableInteger(L, "r12", ctx.r12);
    setTableInteger(L, "r13", ctx.r13);
    setTableInteger(L, "r14", ctx.r14);
    setTableInteger(L, "r15", ctx.r15);
    setTableInteger(L, "rip", ctx.rip);
    setTableInteger(L, "rflags", ctx.rflags);
    lua_setglobal(L, "ctx");
}

bool runConditionChunk(lua_State* L, const std::string& chunk, bool requireResult,
                       bool& matched, std::string& error) {
    const int base = lua_gettop(L);
    if (luaL_loadstring(L, chunk.c_str()) != LUA_OK) {
        error = lua_tostring(L, -1) ? lua_tostring(L, -1) : "failed to compile breakpoint condition";
        lua_settop(L, base);
        return false;
    }

    if (lua_pcall(L, 0, LUA_MULTRET, 0) != LUA_OK) {
        error = lua_tostring(L, -1) ? lua_tostring(L, -1) : "failed to execute breakpoint condition";
        lua_settop(L, base);
        return false;
    }

    if (lua_gettop(L) == base) {
        if (requireResult) {
            error = "breakpoint condition did not return a value";
            lua_settop(L, base);
            return false;
        }
        matched = true;
    } else {
        matched = lua_toboolean(L, -1) != 0;
    }
    lua_settop(L, base);
    error.clear();
    return true;
}

bool conditionMatches(const Breakpoint& bp, const BreakpointHit& hit, std::string& error) {
    if (bp.condition.empty())
        return true;

    std::unique_ptr<lua_State, LuaStateDeleter> L(luaL_newstate());
    if (!L) {
        error = "failed to create Lua state for breakpoint condition";
        return true;
    }

    luaL_openlibs(L.get());
    exposeConditionGlobals(L.get(), bp, hit);

    bool matched = true;
    if (runConditionChunk(L.get(), "return (" + bp.condition + ")", true, matched, error) ||
        runConditionChunk(L.get(), "return " + bp.condition, true, matched, error) ||
        runConditionChunk(L.get(), bp.condition, true, matched, error)) {
        return matched;
    }

    return true;
}

} // namespace

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

bool BreakpointManager::recordHit(int id, const BreakpointHit& hit) {
    Breakpoint bpSnapshot;
    {
        std::lock_guard lock(mutex_);
        auto it = std::find_if(breakpoints_.begin(), breakpoints_.end(),
            [id](const Breakpoint& b) { return b.id == id; });
        if (it == breakpoints_.end())
            return false;
        bpSnapshot = *it;
    }
    if (!bpSnapshot.enabled)
        return false;

    std::string conditionError;
    if (!conditionMatches(bpSnapshot, hit, conditionError))
        return false;
    if (!conditionError.empty()) {
        std::fprintf(stderr, "Breakpoint %d condition error: %s\n",
            id, conditionError.c_str());
    }

    Breakpoint callbackBp;
    HitCallback callback;
    bool notify = false;

    {
        std::lock_guard lock(mutex_);

        bool found = false;
        for (auto& bp : breakpoints_) {
            if (bp.id == id) {
                found = true;
                bp.hitCount++;
                if (bp.oneShot) bp.enabled = false;
                callbackBp = bp;
                notify = static_cast<bool>(hitCallback_);
                if (notify) callback = hitCallback_;
                break;
            }
        }
        if (!found)
            return false;

        hitLog_[id].push_back(hit);

        // Cap log at 10000 entries per breakpoint
        if (hitLog_[id].size() > 10000)
            hitLog_[id].erase(hitLog_[id].begin(), hitLog_[id].begin() + 5000);
    }

    if (notify)
        callback(callbackBp, hit);

    return true;
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
