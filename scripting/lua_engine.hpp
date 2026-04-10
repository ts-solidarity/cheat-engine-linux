#pragma once
/// Lua 5.3 scripting engine with CE API bindings.

#include "platform/process_api.hpp"
#include "scanner/memory_scanner.hpp"
#include "symbols/elf_symbols.hpp"
#include <string>
#include <functional>

struct lua_State;

namespace ce {

class LuaEngine {
public:
    LuaEngine();
    ~LuaEngine();

    LuaEngine(const LuaEngine&) = delete;

    /// Set the target process (enables memory functions in Lua).
    void setProcess(ProcessHandle* proc) { proc_ = proc; }
    void setResolver(SymbolResolver* resolver) { resolver_ = resolver; }

    /// Execute a Lua string. Returns error message or empty on success.
    std::string execute(const std::string& code);

    /// Execute a Lua file.
    std::string executeFile(const std::string& path);

    /// Set a callback for Lua print output.
    void setOutputCallback(std::function<void(const std::string&)> cb) { outputCb_ = std::move(cb); }

    lua_State* state() { return L_; }

    static LuaEngine* instanceFromState(lua_State* L);

    std::function<void(const std::string&)> outputCb_;

private:
    void registerBindings();

    lua_State* L_ = nullptr;
    ProcessHandle* proc_ = nullptr;
    SymbolResolver* resolver_ = nullptr;
};

/// Register extended CE API bindings (defined in lua_bindings.cpp)
void registerExtendedBindings(lua_State* L);

} // namespace ce
