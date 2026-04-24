/// Extended Lua API bindings — CE-compatible function set.
#include "scripting/lua_engine.hpp"
#include "scanner/memory_scanner.hpp"
#include "scanner/pointer_scanner.hpp"
#include "core/autoasm.hpp"
#include "arch/disassembler.hpp"
#include "arch/assembler.hpp"
#include "symbols/elf_symbols.hpp"
#include "platform/linux/linux_process.hpp"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include <cstring>
#include <cstdlib>
#include <fstream>
#include <unistd.h>
#include <filesystem>
#include <limits>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace ce {

// Helper: get process handle from registry
static ProcessHandle* getProc(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* p = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    return p;
}

static SymbolResolver* getResolver(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_resolver");
    auto* r = (SymbolResolver*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    return r;
}

// ── Memory read functions (all widths) ──

static int l_readByte(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    uint8_t v = 0;
    if (p->read(addr, &v, 1)) lua_pushinteger(L, v);
    else lua_pushnil(L);
    return 1;
}

static int l_readSmallInteger(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int16_t v = 0;
    if (p->read(addr, &v, 2)) lua_pushinteger(L, v);
    else lua_pushnil(L);
    return 1;
}

static int l_readQword(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int64_t v = 0;
    if (p->read(addr, &v, 8)) lua_pushinteger(L, v);
    else lua_pushnil(L);
    return 1;
}

static int l_readPointer(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    uintptr_t v = 0;
    if (p->read(addr, &v, sizeof(v))) lua_pushinteger(L, (lua_Integer)v);
    else lua_pushnil(L);
    return 1;
}

static int l_readDouble(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    double v = 0;
    if (p->read(addr, &v, 8)) lua_pushnumber(L, v);
    else lua_pushnil(L);
    return 1;
}

static int l_readString(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int maxLen = luaL_optinteger(L, 2, 256);
    std::vector<char> buf(maxLen + 1, 0);
    auto r = p->read(addr, buf.data(), maxLen);
    if (r) {
        buf[*r] = 0;
        lua_pushstring(L, buf.data());
    } else lua_pushnil(L);
    return 1;
}

// ── Memory write functions ──

static int l_writeByte(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    uint8_t v = (uint8_t)luaL_checkinteger(L, 2);
    p->write(addr, &v, 1);
    return 0;
}

static int l_writeSmallInteger(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int16_t v = (int16_t)luaL_checkinteger(L, 2);
    p->write(addr, &v, 2);
    return 0;
}

static int l_writeQword(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int64_t v = luaL_checkinteger(L, 2);
    p->write(addr, &v, 8);
    return 0;
}

static int l_writeDouble(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    double v = luaL_checknumber(L, 2);
    p->write(addr, &v, 8);
    return 0;
}

static int l_writeString(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    const char* s = luaL_checkstring(L, 2);
    p->write(addr, s, strlen(s) + 1);
    return 0;
}

static int l_writeBytes(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);
    int n = (int)lua_rawlen(L, 2);
    std::vector<uint8_t> bytes(n);
    for (int i = 1; i <= n; ++i) {
        lua_rawgeti(L, 2, i);
        bytes[i-1] = (uint8_t)lua_tointeger(L, -1);
        lua_pop(L, 1);
    }
    p->write(addr, bytes.data(), bytes.size());
    return 0;
}

// ── Local memory read/write functions ──

template <typename T>
static T readLocalValue(uintptr_t addr) {
    T value{};
    std::memcpy(&value, reinterpret_cast<const void*>(addr), sizeof(T));
    return value;
}

template <typename T>
static void writeLocalValue(uintptr_t addr, T value) {
    std::memcpy(reinterpret_cast<void*>(addr), &value, sizeof(T));
}

static int l_readByteLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushinteger(L, readLocalValue<uint8_t>(addr));
    return 1;
}

static int l_readSmallIntegerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushinteger(L, readLocalValue<int16_t>(addr));
    return 1;
}

static int l_readIntegerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushinteger(L, readLocalValue<int32_t>(addr));
    return 1;
}

static int l_readQwordLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushinteger(L, readLocalValue<int64_t>(addr));
    return 1;
}

static int l_readPointerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushinteger(L, (lua_Integer)readLocalValue<uintptr_t>(addr));
    return 1;
}

static int l_readFloatLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushnumber(L, readLocalValue<float>(addr));
    return 1;
}

static int l_readDoubleLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushnumber(L, readLocalValue<double>(addr));
    return 1;
}

static int l_readBytesLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int size = luaL_checkinteger(L, 2);
    luaL_argcheck(L, size >= 0, 2, "size must be non-negative");

    auto* bytes = reinterpret_cast<const uint8_t*>(addr);
    lua_newtable(L);
    for (int i = 0; i < size; ++i) {
        lua_pushinteger(L, bytes[i]);
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

static int l_readStringLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int maxLen = luaL_optinteger(L, 2, 256);
    luaL_argcheck(L, maxLen >= 0, 2, "max length must be non-negative");

    auto* str = reinterpret_cast<const char*>(addr);
    lua_pushlstring(L, str, strnlen(str, maxLen));
    return 1;
}

static int l_writeByteLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<uint8_t>(addr, (uint8_t)luaL_checkinteger(L, 2));
    return 0;
}

static int l_writeSmallIntegerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<int16_t>(addr, (int16_t)luaL_checkinteger(L, 2));
    return 0;
}

static int l_writeIntegerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<int32_t>(addr, (int32_t)luaL_checkinteger(L, 2));
    return 0;
}

static int l_writeQwordLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<int64_t>(addr, (int64_t)luaL_checkinteger(L, 2));
    return 0;
}

static int l_writePointerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<uintptr_t>(addr, (uintptr_t)luaL_checkinteger(L, 2));
    return 0;
}

static int l_writeFloatLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<float>(addr, (float)luaL_checknumber(L, 2));
    return 0;
}

static int l_writeDoubleLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<double>(addr, luaL_checknumber(L, 2));
    return 0;
}

static int l_writeBytesLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);
    int n = (int)lua_rawlen(L, 2);
    auto* bytes = reinterpret_cast<uint8_t*>(addr);
    for (int i = 1; i <= n; ++i) {
        lua_rawgeti(L, 2, i);
        bytes[i - 1] = (uint8_t)lua_tointeger(L, -1);
        lua_pop(L, 1);
    }
    return 0;
}

static int l_writeStringLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    size_t len = 0;
    const char* str = luaL_checklstring(L, 2, &len);
    std::memcpy(reinterpret_cast<void*>(addr), str, len);
    reinterpret_cast<char*>(addr)[len] = '\0';
    return 0;
}

// ── Process info ──

static pid_t parseProcessId(std::string_view text) {
    std::string value(text);
    char* end = nullptr;
    long pid = std::strtol(value.c_str(), &end, 10);
    if (end == value.c_str() || *end != '\0' || pid <= 0 ||
        pid > std::numeric_limits<pid_t>::max()) {
        return 0;
    }
    return static_cast<pid_t>(pid);
}

static std::string readProcessName(const std::filesystem::path& procDir) {
    std::ifstream comm(procDir / "comm");
    std::string name;
    if (comm)
        std::getline(comm, name);
    return name;
}

static bool processNameMatches(const std::filesystem::path& procDir, std::string_view target) {
    if (readProcessName(procDir) == target)
        return true;

    std::error_code ec;
    auto exe = std::filesystem::read_symlink(procDir / "exe", ec);
    return !ec && exe.filename().string() == target;
}

static pid_t findProcessIdByName(std::string_view target) {
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(
             "/proc", std::filesystem::directory_options::skip_permission_denied, ec)) {
        if (ec)
            break;
        auto pid = parseProcessId(entry.path().filename().string());
        if (pid > 0 && processNameMatches(entry.path(), target))
            return pid;
    }
    return 0;
}

static int l_getProcessList(lua_State* L) {
    // Return a table of {pid, name} pairs
    lua_newtable(L);
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(
             "/proc", std::filesystem::directory_options::skip_permission_denied, ec)) {
        if (ec)
            break;
        auto pid = parseProcessId(entry.path().filename().string());
        if (pid <= 0)
            continue;

        auto pname = readProcessName(entry.path());
        lua_newtable(L);
        lua_pushinteger(L, pid);
        lua_setfield(L, -2, "pid");
        lua_pushstring(L, pname.c_str());
        lua_setfield(L, -2, "name");
        lua_rawseti(L, -2, pid);
    }
    return 1;
}

static int l_getProcessIDFromProcessName(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    auto pid = findProcessIdByName(name);
    if (pid > 0)
        lua_pushinteger(L, pid);
    else
        lua_pushnil(L);
    return 1;
}

static int l_getModuleList(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_newtable(L); return 1; }
    auto mods = p->modules();
    lua_newtable(L);
    for (size_t i = 0; i < mods.size(); ++i) {
        lua_newtable(L);
        lua_pushstring(L, mods[i].name.c_str());
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, (lua_Integer)mods[i].base);
        lua_setfield(L, -2, "base");
        lua_pushinteger(L, (lua_Integer)mods[i].size);
        lua_setfield(L, -2, "size");
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

// ── Symbol resolution ──

static int l_getNameFromAddress(lua_State* L) {
    auto* r = getResolver(L);
    if (!r) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    auto name = r->resolve(addr);
    if (!name.empty()) lua_pushstring(L, name.c_str());
    else lua_pushnil(L);
    return 1;
}

static int l_getAddressFromName(lua_State* L) {
    auto* r = getResolver(L);
    if (!r) { lua_pushnil(L); return 1; }
    const char* name = luaL_checkstring(L, 1);
    auto addr = r->lookup(name);
    if (addr) lua_pushinteger(L, (lua_Integer)addr);
    else lua_pushnil(L);
    return 1;
}

// ── Disassembly / Assembly ──

static int l_disassemble(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    uint8_t buf[16];
    auto r = p->read(addr, buf, sizeof(buf));
    if (!r) { lua_pushnil(L); return 1; }

    Disassembler dis(Arch::X86_64);
    auto insns = dis.disassemble(addr, {buf, *r}, 1);
    if (insns.empty()) { lua_pushnil(L); return 1; }

    lua_pushstring(L, (insns[0].mnemonic + " " + insns[0].operands).c_str());
    lua_pushinteger(L, insns[0].size);
    return 2; // returns instruction_text, size
}

static int l_assemble(lua_State* L) {
    const char* code = luaL_checkstring(L, 1);
    uintptr_t addr = (uintptr_t)luaL_optinteger(L, 2, 0);

    Assembler asm64(AsmArch::X86_64);
    auto result = asm64.assemble(code, addr);
    if (!result) {
        lua_pushnil(L);
        lua_pushstring(L, result.error().c_str());
        return 2;
    }

    lua_newtable(L);
    for (size_t i = 0; i < result->size(); ++i) {
        lua_pushinteger(L, (*result)[i]);
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

static int l_autoAssemble(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); lua_pushstring(L, "no process"); return 2; }
    const char* script = luaL_checkstring(L, 1);

    AutoAssembler aa;
    auto result = aa.execute(*p, script);
    lua_pushboolean(L, result.success);
    if (!result.success)
        lua_pushstring(L, result.error.c_str());
    else
        lua_pushnil(L);
    return 2;
}

static int l_autoAssembleCheck(lua_State* L) {
    const char* script = luaL_checkstring(L, 1);

    AutoAssembler aa;
    auto result = aa.check(script);
    lua_pushboolean(L, result.success);
    if (!result.success)
        lua_pushstring(L, result.error.c_str());
    else
        lua_pushnil(L);
    return 2;
}

// ── Utility ──

static int l_showMessage(lua_State* L) {
    const char* msg = luaL_checkstring(L, 1);
    fprintf(stderr, "[CE Lua] %s\n", msg); // GUI integration would use QMessageBox
    return 0;
}

static int l_sleep(lua_State* L) {
    int ms = (int)luaL_checkinteger(L, 1);
    usleep(ms * 1000);
    return 0;
}

static int l_getCheatEngineDir(lua_State* L) {
    char buf[1024];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = 0;
        auto dir = std::filesystem::path(buf).parent_path().string();
        lua_pushstring(L, dir.c_str());
    } else {
        lua_pushstring(L, ".");
    }
    return 1;
}

// ── File I/O ──

static int l_readFromFile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    std::ifstream f(path);
    if (!f) { lua_pushnil(L); return 1; }
    std::string content((std::istreambuf_iterator<char>(f)), {});
    lua_pushlstring(L, content.data(), content.size());
    return 1;
}

static int l_writeToFile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    size_t len;
    const char* data = luaL_checklstring(L, 2, &len);
    std::ofstream f(path, std::ios::binary);
    if (f) { f.write(data, len); lua_pushboolean(L, 1); }
    else lua_pushboolean(L, 0);
    return 1;
}

static int l_fileExists(lua_State* L) {
    lua_pushboolean(L, std::filesystem::exists(luaL_checkstring(L, 1)));
    return 1;
}

static int l_getTempDir(lua_State* L) {
    lua_pushstring(L, std::filesystem::temp_directory_path().c_str());
    return 1;
}

static int l_getProcessDir(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushstring(L, ""); return 1; }
    try {
        auto exe = std::filesystem::read_symlink("/proc/" + std::to_string(p->pid()) + "/exe");
        lua_pushstring(L, exe.parent_path().c_str());
    } catch (...) { lua_pushstring(L, ""); }
    return 1;
}

// ── Scanning from Lua ──

struct LuaScanData {
    MemoryScanner scanner;
    std::unique_ptr<ScanResult> result;
};

static int l_createMemScan(lua_State* L) {
    auto* sd = (LuaScanData*)lua_newuserdata(L, sizeof(LuaScanData));
    new (sd) LuaScanData();
    luaL_getmetatable(L, "MemScan");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        luaL_newmetatable(L, "MemScan");
        lua_pushvalue(L, -1); lua_setfield(L, -2, "__index");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* sd = (LuaScanData*)luaL_checkudata(L, 1, "MemScan");
            sd->~LuaScanData();
            return 0;
        });
        lua_setfield(L, -2, "__gc");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* sd = (LuaScanData*)luaL_checkudata(L, 1, "MemScan");
            auto* p = getProc(L);
            if (!p) { lua_pushboolean(L, 0); return 1; }
            int scanType = (int)luaL_checkinteger(L, 2);
            int valueType = (int)luaL_checkinteger(L, 3);
            const char* value = luaL_checkstring(L, 4);
            ScanConfig cfg;
            cfg.valueType = (ValueType)valueType;
            cfg.compareType = (ScanCompare)scanType;
            cfg.intValue = atoll(value);
            cfg.floatValue = atof(value);
            cfg.alignment = 4;
            sd->result = std::make_unique<ScanResult>(sd->scanner.firstScan(*p, cfg));
            lua_pushboolean(L, 1);
            return 1;
        });
        lua_setfield(L, -2, "firstScan");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* sd = (LuaScanData*)luaL_checkudata(L, 1, "MemScan");
            lua_pushinteger(L, sd->result ? sd->result->count() : 0);
            return 1;
        });
        lua_setfield(L, -2, "getFoundCount");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* sd = (LuaScanData*)luaL_checkudata(L, 1, "MemScan");
            int idx = (int)luaL_checkinteger(L, 2);
            if (!sd->result || idx < 0 || idx >= (int)sd->result->count()) { lua_pushnil(L); return 1; }
            lua_pushinteger(L, (lua_Integer)sd->result->address(idx));
            return 1;
        });
        lua_setfield(L, -2, "getAddress");
    }
    lua_setmetatable(L, -2);
    return 1;
}

// ── Debug control ──

static int l_debug_getThreadList(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_newtable(L); return 1; }
    auto threads = p->threads();
    lua_newtable(L);
    for (size_t i = 0; i < threads.size(); ++i) {
        lua_pushinteger(L, threads[i].tid);
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

// ── Address list manipulation ──

static int l_addressList_getCount(lua_State* L) {
    // Stored as registry value by MainWindow
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_addresslist_count");
    if (lua_isfunction(L, -1)) {
        lua_call(L, 0, 1);
        return 1;
    }
    lua_pop(L, 1);
    lua_pushinteger(L, 0);
    return 1;
}

// ── Additional CE-compatible functions ──

static int l_openProcess(lua_State* L) {
    const char* nameOrPid = luaL_checkstring(L, 1);
    auto pid = parseProcessId(nameOrPid);
    if (pid <= 0)
        pid = findProcessIdByName(nameOrPid);

    if (pid > 0) {
        auto* engine = LuaEngine::instanceFromState(L);
        if (engine) {
            os::LinuxProcessEnumerator enumerator;
            auto proc = enumerator.open(pid);
            if (proc) {
                engine->setOwnedProcess(std::move(proc));
                lua_pushinteger(L, pid);
                return 1;
            }
        }
    }

    lua_pushnil(L);
    return 1;
}

static int l_getOpenedProcessID(lua_State* L) {
    auto* p = getProc(L);
    lua_pushinteger(L, p ? p->pid() : 0);
    return 1;
}

static int l_writePointer(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    uintptr_t val = (uintptr_t)luaL_checkinteger(L, 2);
    p->write(addr, &val, sizeof(val));
    return 0;
}

static int l_registerSymbol(lua_State* L) {
    auto* r = getResolver(L);
    // For now, store in a global table in Lua registry
    const char* name = luaL_checkstring(L, 1);
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 2);
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_user_symbols");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setfield(L, LUA_REGISTRYINDEX, "ce_user_symbols");
    }
    lua_pushinteger(L, (lua_Integer)addr);
    lua_setfield(L, -2, name);
    lua_pop(L, 1);
    return 0;
}

static int l_unregisterSymbol(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_user_symbols");
    if (!lua_isnil(L, -1)) {
        lua_pushnil(L);
        lua_setfield(L, -2, name);
    }
    lua_pop(L, 1);
    return 0;
}

static int l_inputQuery(lua_State* L) {
    const char* title = luaL_checkstring(L, 1);
    const char* prompt = luaL_checkstring(L, 2);
    const char* defval = luaL_optstring(L, 3, "");
    // In GUI mode, would use QInputDialog; for now, stderr prompt
    fprintf(stderr, "[CE Lua] %s: %s [%s]: ", title, prompt, defval);
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin)) {
        buf[strcspn(buf, "\n")] = 0;
        if (buf[0] == 0) lua_pushstring(L, defval);
        else lua_pushstring(L, buf);
    } else {
        lua_pushstring(L, defval);
    }
    return 1;
}

static int l_shellExecute(lua_State* L) {
    const char* cmd = luaL_checkstring(L, 1);
    int ret = system(cmd);
    lua_pushinteger(L, ret);
    return 1;
}

static int l_getScreenWidth(lua_State* L) {
    // Basic X11 screen size
    lua_pushinteger(L, 1920); // Default; would query X11
    return 1;
}

static int l_getScreenHeight(lua_State* L) {
    lua_pushinteger(L, 1080);
    return 1;
}

static int l_inMainThread(lua_State* L) {
    lua_pushboolean(L, 1); // Simplified
    return 1;
}

static int l_getThreadList(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_newtable(L); return 1; }
    auto threads = p->threads();
    lua_newtable(L);
    for (size_t i = 0; i < threads.size(); ++i) {
        lua_pushinteger(L, threads[i].tid);
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

static int l_readRegionFromFile(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    const char* filename = luaL_checkstring(L, 1);
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 2);
    std::ifstream f(filename, std::ios::binary);
    if (!f) { lua_pushboolean(L, 0); return 1; }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), {});
    auto r = p->write(addr, data.data(), data.size());
    lua_pushboolean(L, r.has_value());
    return 1;
}

static int l_writeRegionToFile(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    const char* filename = luaL_checkstring(L, 1);
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 2);
    size_t size = (size_t)luaL_checkinteger(L, 3);
    std::vector<uint8_t> buf(size);
    auto r = p->read(addr, buf.data(), size);
    if (!r) { lua_pushboolean(L, 0); return 1; }
    std::ofstream f(filename, std::ios::binary);
    if (f) { f.write((char*)buf.data(), *r); lua_pushboolean(L, 1); }
    else lua_pushboolean(L, 0);
    return 1;
}

static int l_AOBScan(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    const char* pattern = luaL_checkstring(L, 1);
    ScanConfig cfg;
    cfg.valueType = ValueType::ByteArray;
    cfg.parseAOB(pattern);
    cfg.alignment = 1;
    MemoryScanner scanner;
    auto result = scanner.firstScan(*p, cfg);
    if (result.count() > 0)
        lua_pushinteger(L, (lua_Integer)result.address(0));
    else
        lua_pushnil(L);
    return 1;
}

static int l_AOBScanEx(lua_State* L) {
    // Returns all results as a table
    auto* p = getProc(L);
    if (!p) { lua_newtable(L); return 1; }
    const char* pattern = luaL_checkstring(L, 1);
    ScanConfig cfg;
    cfg.valueType = ValueType::ByteArray;
    cfg.parseAOB(pattern);
    cfg.alignment = 1;
    MemoryScanner scanner;
    auto result = scanner.firstScan(*p, cfg);
    lua_newtable(L);
    size_t count = std::min(result.count(), size_t(1000));
    for (size_t i = 0; i < count; ++i) {
        lua_pushinteger(L, (lua_Integer)result.address(i));
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

static int l_fullAccess(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    size_t size = (size_t)luaL_checkinteger(L, 2);
    p->protect(addr, size, MemProt::All);
    return 0;
}

// ── Constants registration ──

static void registerConstants(lua_State* L) {
    // Scan types (CE compatible)
    lua_pushinteger(L, 0); lua_setglobal(L, "soExactValue");
    lua_pushinteger(L, 1); lua_setglobal(L, "soValueBetween");
    lua_pushinteger(L, 2); lua_setglobal(L, "soBiggerThan");
    lua_pushinteger(L, 3); lua_setglobal(L, "soSmallerThan");
    lua_pushinteger(L, 4); lua_setglobal(L, "soUnknownValue");
    lua_pushinteger(L, 5); lua_setglobal(L, "soIncreasedValue");
    lua_pushinteger(L, 6); lua_setglobal(L, "soDecreasedValue");
    lua_pushinteger(L, 7); lua_setglobal(L, "soChanged");
    lua_pushinteger(L, 8); lua_setglobal(L, "soUnchanged");

    // Value types (CE compatible)
    lua_pushinteger(L, 0); lua_setglobal(L, "vtByte");
    lua_pushinteger(L, 1); lua_setglobal(L, "vtWord");
    lua_pushinteger(L, 2); lua_setglobal(L, "vtDword");
    lua_pushinteger(L, 3); lua_setglobal(L, "vtQword");
    lua_pushinteger(L, 4); lua_setglobal(L, "vtSingle");
    lua_pushinteger(L, 5); lua_setglobal(L, "vtDouble");
    lua_pushinteger(L, 6); lua_setglobal(L, "vtString");
    lua_pushinteger(L, 8); lua_setglobal(L, "vtByteArray");
    lua_pushinteger(L, 9); lua_setglobal(L, "vtBinary");
    lua_pushinteger(L, 10); lua_setglobal(L, "vtAll");

    // Breakpoint types
    lua_pushinteger(L, 0); lua_setglobal(L, "bptExecute");
    lua_pushinteger(L, 1); lua_setglobal(L, "bptWrite");
    lua_pushinteger(L, 3); lua_setglobal(L, "bptAccess");

    // Virtual key codes (common ones)
    lua_pushinteger(L, 0x70); lua_setglobal(L, "VK_F1");
    lua_pushinteger(L, 0x71); lua_setglobal(L, "VK_F2");
    lua_pushinteger(L, 0x72); lua_setglobal(L, "VK_F3");
    lua_pushinteger(L, 0x73); lua_setglobal(L, "VK_F4");
    lua_pushinteger(L, 0x74); lua_setglobal(L, "VK_F5");
    lua_pushinteger(L, 0x75); lua_setglobal(L, "VK_F6");
    lua_pushinteger(L, 0x76); lua_setglobal(L, "VK_F7");
    lua_pushinteger(L, 0x77); lua_setglobal(L, "VK_F8");
    lua_pushinteger(L, 0x78); lua_setglobal(L, "VK_F9");
    lua_pushinteger(L, 0x79); lua_setglobal(L, "VK_F10");
    lua_pushinteger(L, 0x7A); lua_setglobal(L, "VK_F11");
    lua_pushinteger(L, 0x7B); lua_setglobal(L, "VK_F12");
    lua_pushinteger(L, 0x13); lua_setglobal(L, "VK_PAUSE");
    lua_pushinteger(L, 0x0D); lua_setglobal(L, "VK_RETURN");
    lua_pushinteger(L, 0x20); lua_setglobal(L, "VK_SPACE");
    lua_pushinteger(L, 0x1B); lua_setglobal(L, "VK_ESCAPE");
}

// ── Registration function called from LuaEngine ──

void registerExtendedBindings(lua_State* L) {
    // Memory read
    lua_register(L, "readByte", l_readByte);
    lua_register(L, "readSmallInteger", l_readSmallInteger);
    lua_register(L, "readQword", l_readQword);
    lua_register(L, "readPointer", l_readPointer);
    lua_register(L, "readDouble", l_readDouble);
    lua_register(L, "readString", l_readString);

    // Memory write
    lua_register(L, "writeByte", l_writeByte);
    lua_register(L, "writeSmallInteger", l_writeSmallInteger);
    lua_register(L, "writeQword", l_writeQword);
    lua_register(L, "writeDouble", l_writeDouble);
    lua_register(L, "writeString", l_writeString);
    lua_register(L, "writeBytes", l_writeBytes);

    // Local memory
    lua_register(L, "readByteLocal", l_readByteLocal);
    lua_register(L, "readSmallIntegerLocal", l_readSmallIntegerLocal);
    lua_register(L, "readIntegerLocal", l_readIntegerLocal);
    lua_register(L, "readQwordLocal", l_readQwordLocal);
    lua_register(L, "readPointerLocal", l_readPointerLocal);
    lua_register(L, "readFloatLocal", l_readFloatLocal);
    lua_register(L, "readDoubleLocal", l_readDoubleLocal);
    lua_register(L, "readBytesLocal", l_readBytesLocal);
    lua_register(L, "readStringLocal", l_readStringLocal);
    lua_register(L, "writeByteLocal", l_writeByteLocal);
    lua_register(L, "writeSmallIntegerLocal", l_writeSmallIntegerLocal);
    lua_register(L, "writeIntegerLocal", l_writeIntegerLocal);
    lua_register(L, "writeQwordLocal", l_writeQwordLocal);
    lua_register(L, "writePointerLocal", l_writePointerLocal);
    lua_register(L, "writeFloatLocal", l_writeFloatLocal);
    lua_register(L, "writeDoubleLocal", l_writeDoubleLocal);
    lua_register(L, "writeBytesLocal", l_writeBytesLocal);
    lua_register(L, "writeStringLocal", l_writeStringLocal);

    // Process info
    lua_register(L, "getProcessList", l_getProcessList);
    lua_register(L, "getProcessIDFromProcessName", l_getProcessIDFromProcessName);
    lua_register(L, "getModuleList", l_getModuleList);

    // Symbols
    lua_register(L, "getNameFromAddress", l_getNameFromAddress);
    lua_register(L, "getAddressFromName", l_getAddressFromName);

    // Disassembly / Assembly
    lua_register(L, "disassemble", l_disassemble);
    lua_register(L, "assemble", l_assemble);
    lua_register(L, "autoAssemble", l_autoAssemble);
    lua_register(L, "autoAssembleCheck", l_autoAssembleCheck);

    // Utility
    lua_register(L, "showMessage", l_showMessage);
    lua_register(L, "sleep", l_sleep);
    lua_register(L, "getCheatEngineDir", l_getCheatEngineDir);

    // File I/O
    lua_register(L, "readFile", l_readFromFile);
    lua_register(L, "writeFile", l_writeToFile);
    lua_register(L, "readFromFile", l_readFromFile);
    lua_register(L, "writeToFile", l_writeToFile);
    lua_register(L, "fileExists", l_fileExists);
    lua_register(L, "getTempDir", l_getTempDir);
    lua_register(L, "getProcessDir", l_getProcessDir);

    // Scanning
    lua_register(L, "createMemScan", l_createMemScan);

    // Debug
    lua_register(L, "debug_getThreadList", l_debug_getThreadList);

    // Address list
    lua_register(L, "addressList_getCount", l_addressList_getCount);

    // Process
    lua_register(L, "openProcess", l_openProcess);
    lua_register(L, "getOpenedProcessID", l_getOpenedProcessID);
    lua_register(L, "getThreadList", l_getThreadList);

    // Extended memory
    lua_register(L, "writePointer", l_writePointer);

    // Symbols
    lua_register(L, "registerSymbol", l_registerSymbol);
    lua_register(L, "unregisterSymbol", l_unregisterSymbol);

    // AOB
    lua_register(L, "AOBScan", l_AOBScan);
    lua_register(L, "AOBScanEx", l_AOBScanEx);

    // Memory protection
    lua_register(L, "fullAccess", l_fullAccess);

    // File regions
    lua_register(L, "readRegionFromFile", l_readRegionFromFile);
    lua_register(L, "writeRegionToFile", l_writeRegionToFile);

    // UI
    lua_register(L, "inputQuery", l_inputQuery);
    lua_register(L, "shellExecute", l_shellExecute);
    lua_register(L, "getScreenWidth", l_getScreenWidth);
    lua_register(L, "getScreenHeight", l_getScreenHeight);

    // Misc
    lua_register(L, "inMainThread", l_inMainThread);

    // Constants
    registerConstants(L);
}

} // namespace ce
