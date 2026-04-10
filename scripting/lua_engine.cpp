#include "scripting/lua_engine.hpp"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include <cstring>

namespace ce {

// Store engine pointer in Lua registry
static const char* ENGINE_KEY = "ce_engine";

LuaEngine* LuaEngine::instanceFromState(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, ENGINE_KEY);
    auto* eng = (LuaEngine*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    return eng;
}

// ── Lua bindings ──

static int l_readInteger(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* proc = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!proc) { lua_pushnil(L); return 1; }

    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int32_t val = 0;
    auto r = proc->read(addr, &val, sizeof(val));
    if (r) lua_pushinteger(L, val);
    else lua_pushnil(L);
    return 1;
}

static int l_writeInteger(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* proc = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!proc) return 0;

    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int32_t val = (int32_t)luaL_checkinteger(L, 2);
    proc->write(addr, &val, sizeof(val));
    return 0;
}

static int l_readFloat(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* proc = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!proc) { lua_pushnil(L); return 1; }

    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    float val = 0;
    auto r = proc->read(addr, &val, sizeof(val));
    if (r) lua_pushnumber(L, val);
    else lua_pushnil(L);
    return 1;
}

static int l_writeFloat(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* proc = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!proc) return 0;

    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    float val = (float)luaL_checknumber(L, 2);
    proc->write(addr, &val, sizeof(val));
    return 0;
}

static int l_readBytes(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* proc = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!proc) { lua_pushnil(L); return 1; }

    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int size = (int)luaL_checkinteger(L, 2);
    std::vector<uint8_t> buf(size);
    auto r = proc->read(addr, buf.data(), size);
    if (r) {
        lua_newtable(L);
        for (int i = 0; i < (int)*r; ++i) {
            lua_pushinteger(L, buf[i]);
            lua_rawseti(L, -2, i + 1);
        }
    } else {
        lua_pushnil(L);
    }
    return 1;
}

static int l_getAddress(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_resolver");
    auto* resolver = (SymbolResolver*)lua_touserdata(L, -1);
    lua_pop(L, 1);

    const char* name = luaL_checkstring(L, 1);
    uintptr_t addr = 0;
    if (resolver) addr = resolver->lookup(name);
    if (addr)
        lua_pushinteger(L, (lua_Integer)addr);
    else
        lua_pushnil(L);
    return 1;
}

static int l_getModuleBase(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* proc = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!proc) { lua_pushnil(L); return 1; }

    const char* name = luaL_checkstring(L, 1);
    auto mods = proc->modules();
    for (auto& m : mods) {
        if (m.name == name) {
            lua_pushinteger(L, (lua_Integer)m.base);
            return 1;
        }
    }
    lua_pushnil(L);
    return 1;
}

static int l_getProcessId(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* proc = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!proc) { lua_pushinteger(L, 0); return 1; }
    lua_pushinteger(L, proc->pid());
    return 1;
}

// ── Engine implementation ──

LuaEngine::LuaEngine() {
    L_ = luaL_newstate();
    luaL_openlibs(L_);

    // Store engine pointer
    lua_pushlightuserdata(L_, this);
    lua_setfield(L_, LUA_REGISTRYINDEX, ENGINE_KEY);

    registerBindings();
}

LuaEngine::~LuaEngine() {
    if (L_) lua_close(L_);
}

void LuaEngine::registerBindings() {
    // Override print
    lua_pushcfunction(L_, [](lua_State* L) -> int {
        auto* eng = LuaEngine::instanceFromState(L);
        int n = lua_gettop(L);
        std::string out;
        for (int i = 1; i <= n; ++i) {
            if (i > 1) out += "\t";
            out += luaL_tolstring(L, i, nullptr);
            lua_pop(L, 1);
        }
        if (eng && eng->outputCb_)
            eng->outputCb_(out);
        else
            fprintf(stdout, "%s\n", out.c_str());
        return 0;
    });
    lua_setglobal(L_, "print");

    // Core memory functions
    lua_register(L_, "readInteger", l_readInteger);
    lua_register(L_, "writeInteger", l_writeInteger);
    lua_register(L_, "readFloat", l_readFloat);
    lua_register(L_, "writeFloat", l_writeFloat);
    lua_register(L_, "readBytes", l_readBytes);
    lua_register(L_, "getAddress", l_getAddress);
    lua_register(L_, "getModuleBase", l_getModuleBase);
    lua_register(L_, "getProcessID", l_getProcessId);

    // Store process and resolver pointers (updated when setProcess/setResolver called)
    lua_pushlightuserdata(L_, nullptr);
    lua_setfield(L_, LUA_REGISTRYINDEX, "ce_proc");
    lua_pushlightuserdata(L_, nullptr);
    lua_setfield(L_, LUA_REGISTRYINDEX, "ce_resolver");

    // Register extended bindings (readByte, readString, disassemble, autoAssemble, etc.)
    registerExtendedBindings(L_);
}

std::string LuaEngine::execute(const std::string& code) {
    // Update process/resolver pointers
    lua_pushlightuserdata(L_, proc_);
    lua_setfield(L_, LUA_REGISTRYINDEX, "ce_proc");
    lua_pushlightuserdata(L_, resolver_);
    lua_setfield(L_, LUA_REGISTRYINDEX, "ce_resolver");

    if (luaL_dostring(L_, code.c_str()) != LUA_OK) {
        std::string err = lua_tostring(L_, -1);
        lua_pop(L_, 1);
        return err;
    }
    return {};
}

std::string LuaEngine::executeFile(const std::string& path) {
    lua_pushlightuserdata(L_, proc_);
    lua_setfield(L_, LUA_REGISTRYINDEX, "ce_proc");
    lua_pushlightuserdata(L_, resolver_);
    lua_setfield(L_, LUA_REGISTRYINDEX, "ce_resolver");

    if (luaL_dofile(L_, path.c_str()) != LUA_OK) {
        std::string err = lua_tostring(L_, -1);
        lua_pop(L_, 1);
        return err;
    }
    return {};
}

} // namespace ce
