#pragma once
/// Lua GUI bindings — create Qt widgets from Lua scripts.

struct lua_State;

namespace ce {
void registerLuaGuiBindings(lua_State* L);
} // namespace ce
