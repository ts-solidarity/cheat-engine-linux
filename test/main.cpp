#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "core/autoasm.hpp"
#include "core/ct_file.hpp"
#include "debug/breakpoint_manager.hpp"
#include "scripting/lua_engine.hpp"

#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <csignal>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

using namespace ce;
using namespace ce::os;

static void test_cheat_table_json() {
    printf("\n── Test: CheatTable Round Trip ──\n");

    CheatTable table;
    table.gameName = "Example Game";
    table.gameVersion = "1.2.3";
    table.author = "cecore";
    table.comment = "Lua table metadata";
    table.luaScript = "print('table lua')\nreturn 7\n";

    CheatEntry entry;
    entry.id = 7;
    entry.description = "Health \"current\"";
    entry.address = 0x1234;
    entry.type = ValueType::Int32;
    entry.value = "100\n200";
    entry.active = true;
    entry.autoAsmScript = "[ENABLE]\nassert(1234, 90)\n";
    entry.luaScript = "print('entry lua')\n";
    entry.color = "FF00AA";
    entry.dropdownList = "0:Off;1:On";
    entry.hotkeyKeys = "Ctrl+H";
    table.entries.push_back(entry);

    auto jsonPath = std::filesystem::temp_directory_path() /
        ("cecore-table-" + std::to_string(getpid()) + ".json");
    auto xmlPath = std::filesystem::temp_directory_path() /
        ("cecore-table-" + std::to_string(getpid()) + ".CT");

    if (!table.saveJson(jsonPath.string()) || !table.save(xmlPath.string())) {
        printf("  Save FAILED\n");
        return;
    }

    auto matchesTable = [&table, &entry](const CheatTable& loaded) {
        return loaded.gameName == table.gameName &&
            loaded.gameVersion == table.gameVersion &&
            loaded.author == table.author &&
            loaded.comment == table.comment &&
            loaded.luaScript == table.luaScript &&
            loaded.entries.size() == 1 &&
            loaded.entries[0].id == entry.id &&
            loaded.entries[0].description == entry.description &&
            loaded.entries[0].address == entry.address &&
            loaded.entries[0].type == entry.type &&
            loaded.entries[0].value == entry.value &&
            loaded.entries[0].active == entry.active &&
            loaded.entries[0].autoAsmScript == entry.autoAsmScript &&
            loaded.entries[0].luaScript == entry.luaScript &&
            loaded.entries[0].color == entry.color &&
            loaded.entries[0].dropdownList == entry.dropdownList &&
            loaded.entries[0].hotkeyKeys == entry.hotkeyKeys;
    };

    CheatTable jsonLoaded;
    bool jsonOk = jsonLoaded.loadJson(jsonPath.string()) && matchesTable(jsonLoaded);
    CheatTable xmlLoaded;
    bool xmlOk = xmlLoaded.load(xmlPath.string()) && matchesTable(xmlLoaded);
    std::filesystem::remove(jsonPath);
    std::filesystem::remove(xmlPath);

    printf("  JSON round trip: %s\n", jsonOk ? "OK" : "FAILED");
    printf("  CT XML round trip: %s\n", xmlOk ? "OK" : "FAILED");
}

static void test_autoassembler_unregister_symbol(pid_t pid) {
    printf("\n── Test: AutoAssembler unregistersymbol ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;
    aa.registerSymbol("stale_symbol", 0x1234);

    auto result = aa.execute(proc, "[ENABLE]\nunregistersymbol(stale_symbol)\n");
    bool ok = result.success && aa.resolveSymbol("stale_symbol") == 0;
    printf("  unregistersymbol: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_dealloc(pid_t pid) {
    printf("\n── Test: AutoAssembler dealloc ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;

    auto allocResult = aa.execute(proc, "[ENABLE]\nalloc(tempblock, 4096)\n");
    auto deallocResult = aa.execute(proc, "[ENABLE]\ndealloc(tempblock)\n");

    bool sawDeallocLog = false;
    for (const auto& line : deallocResult.log) {
        if (line == "DEALLOC: tempblock") {
            sawDeallocLog = true;
            break;
        }
    }

    bool ok = allocResult.success && deallocResult.success && sawDeallocLog;
    printf("  dealloc: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_data_directive_widths(pid_t pid) {
    printf("\n── Test: AutoAssembler db/dw/dd/dq widths ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;

    auto allocResult = proc.allocate(4096, MemProt::All);
    if (!allocResult) {
        printf("  db/dw/dd/dq widths: FAILED\n");
        return;
    }
    uintptr_t addr = *allocResult;

    char script[512];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "%lx:\n"
        "db 01, \"A\"\n"
        "dw 0203\n"
        "dd 04050607\n"
        "dq 08090A0B0C0D0E0F\n",
        addr);

    auto result = aa.execute(proc, script);
    const uint8_t expected[] = {
        0x01, 0x41,
        0x03, 0x02,
        0x07, 0x06, 0x05, 0x04,
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
    };
    uint8_t actual[sizeof(expected)] = {};
    proc.read(addr, actual, sizeof(actual));

    auto badResult = aa.execute(proc,
        "[ENABLE]\n"
        "alloc(widthbad, 16)\n"
        "widthbad:\n"
        "dw 10000\n");

    bool ok = result.success &&
        std::memcmp(actual, expected, sizeof(actual)) == 0 &&
        !badResult.success &&
        badResult.error.find("out of range") != std::string::npos;

    proc.free(addr, 4096);
    printf("  db/dw/dd/dq widths: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_nop_fillmem(pid_t pid) {
    printf("\n── Test: AutoAssembler nop/fillmem ──\n");

    LinuxProcessHandle proc(pid);
    auto allocResult = proc.allocate(4096, MemProt::All);
    if (!allocResult) {
        printf("  nop/fillmem: FAILED\n");
        return;
    }
    uintptr_t addr = *allocResult;

    char script[256];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "%lx:\n"
        "nop 3\n"
        "fillmem(%lx+3, 4, CC)\n",
        addr, addr);

    AutoAssembler aa;
    auto result = aa.execute(proc, script);
    uint8_t actual[7] = {};
    proc.read(addr, actual, sizeof(actual));
    const uint8_t expected[] = {0x90, 0x90, 0x90, 0xcc, 0xcc, 0xcc, 0xcc};

    bool ok = result.success && std::memcmp(actual, expected, sizeof(actual)) == 0;
    proc.free(addr, 4096);
    printf("  nop/fillmem: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_ds(pid_t pid) {
    printf("\n── Test: AutoAssembler ds ──\n");

    LinuxProcessHandle proc(pid);
    auto allocResult = proc.allocate(4096, MemProt::All);
    if (!allocResult) {
        printf("  ds: FAILED\n");
        return;
    }
    uintptr_t addr = *allocResult;

    char script[256];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "%lx:\n"
        "ds \"hello\"\n",
        addr);

    AutoAssembler aa;
    auto result = aa.execute(proc, script);
    char actual[5] = {};
    proc.read(addr, actual, sizeof(actual));

    bool ok = result.success && std::memcmp(actual, "hello", sizeof(actual)) == 0;
    proc.free(addr, 4096);
    printf("  ds: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_loadbinary(pid_t pid) {
    printf("\n── Test: AutoAssembler loadbinary ──\n");

    LinuxProcessHandle proc(pid);
    auto allocResult = proc.allocate(4096, MemProt::All);
    if (!allocResult) {
        printf("  loadbinary: FAILED\n");
        return;
    }
    uintptr_t addr = *allocResult;

    auto path = std::filesystem::temp_directory_path() /
        ("cecore-loadbinary-" + std::to_string(getpid()) + ".bin");
    const uint8_t expected[] = {0xde, 0xad, 0xbe, 0xef, 0x42};
    {
        std::ofstream f(path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(expected), sizeof(expected));
    }

    char script[512];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "loadbinary(%lx, \"%s\")\n",
        addr, path.c_str());

    AutoAssembler aa;
    auto result = aa.execute(proc, script);
    uint8_t actual[sizeof(expected)] = {};
    proc.read(addr, actual, sizeof(actual));

    bool ok = result.success && std::memcmp(actual, expected, sizeof(actual)) == 0;
    std::filesystem::remove(path);
    proc.free(addr, 4096);
    printf("  loadbinary: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_aobscanmodule(pid_t pid) {
    printf("\n── Test: AutoAssembler aobscanmodule ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;

    auto result = aa.execute(proc,
        "[ENABLE]\n"
        "aobscanmodule(sleep_elf, sleep, 7F 45 4C 46)\n"
        "registersymbol(sleep_elf)\n");

    bool ok = result.success && aa.resolveSymbol("sleep_elf") != 0;
    printf("  aobscanmodule: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_aobscanregion(pid_t pid) {
    printf("\n── Test: AutoAssembler aobscanregion ──\n");

    LinuxProcessHandle proc(pid);
    auto modules = proc.modules();
    auto sleepModule = std::find_if(modules.begin(), modules.end(), [](const ModuleInfo& module) {
        return module.name == "sleep";
    });
    if (sleepModule == modules.end()) {
        printf("  aobscanregion: FAILED\n");
        return;
    }

    char script[256];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "aobscanregion(sleep_elf_region, %lx, %lx, 7F 45 4C 46)\n"
        "registersymbol(sleep_elf_region)\n",
        sleepModule->base, sleepModule->base + sleepModule->size);

    AutoAssembler aa;
    auto result = aa.execute(proc, script);
    bool ok = result.success && aa.resolveSymbol("sleep_elf_region") != 0;
    printf("  aobscanregion: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_aobscanall(pid_t pid) {
    printf("\n── Test: AutoAssembler aobscanall ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;

    auto result = aa.execute(proc,
        "[ENABLE]\n"
        "aobscanall(sleep_elf_all, 7F 45 4C 46)\n"
        "registersymbol(sleep_elf_all)\n");

    bool ok = result.success && aa.resolveSymbol("sleep_elf_all") != 0;
    printf("  aobscanall: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_requires_target(pid_t pid) {
    printf("\n── Test: AutoAssembler requires target ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;

    auto result = aa.execute(proc, "[ENABLE]\nmov eax, 1\n");
    bool ok = !result.success && result.error.find("No active assembly address") != std::string::npos;
    printf("  missing target: %s\n", ok ? "OK" : "FAILED");
}

static void test_breakpoint_conditions() {
    printf("\n── Test: Breakpoint Lua Conditions ──\n");

    BreakpointManager mgr;

    Breakpoint falseBp;
    falseBp.address = 0x401000;
    falseBp.condition = "rax == 2";
    int falseId = mgr.add(falseBp);

    Breakpoint trueBp;
    trueBp.address = 0x401010;
    trueBp.condition = "RAX == 1 and bpId == 2 and hitCount == 1 and bp.id == 2 and ctx.rip == rip";
    int trueId = mgr.add(trueBp);

    BreakpointHit hit{};
    hit.bpId = falseId;
    hit.address = falseBp.address;
    hit.rip = 0x401000;
    hit.tid = 77;
    hit.context.rax = 1;
    hit.context.rip = hit.rip;

    bool falseMatched = mgr.recordHit(falseId, hit);

    hit.bpId = trueId;
    hit.address = trueBp.address;
    hit.rip = 0x401010;
    hit.context.rip = hit.rip;
    bool trueMatched = mgr.recordHit(trueId, hit);

    auto bps = mgr.list();
    auto falseIt = std::find_if(bps.begin(), bps.end(), [falseId](const Breakpoint& bp) {
        return bp.id == falseId;
    });
    auto trueIt = std::find_if(bps.begin(), bps.end(), [trueId](const Breakpoint& bp) {
        return bp.id == trueId;
    });

    bool ok = !falseMatched && trueMatched &&
        falseIt != bps.end() && falseIt->hitCount == 0 &&
        trueIt != bps.end() && trueIt->hitCount == 1 &&
        mgr.getHits(falseId).empty() && mgr.getHits(trueId).size() == 1;

    printf("  Lua condition gate: %s\n", ok ? "OK" : "FAILED");
}

static void test_one_shot_breakpoints() {
    printf("\n── Test: One-shot breakpoints ──\n");

    BreakpointManager mgr;
    Breakpoint bp;
    bp.address = 0x5000;
    bp.oneShot = true;
    int id = mgr.add(bp);

    BreakpointHit hit{};
    hit.bpId = id;
    hit.address = bp.address;
    hit.rip = bp.address;
    hit.context.rip = hit.rip;

    bool firstMatched = mgr.recordHit(id, hit);
    bool secondMatched = mgr.recordHit(id, hit);
    auto bps = mgr.list();
    bool stillListed = std::any_of(bps.begin(), bps.end(), [id](const Breakpoint& listed) {
        return listed.id == id;
    });

    bool ok = firstMatched && !secondMatched && !stillListed && mgr.getHits(id).size() == 1;
    printf("  auto-remove after hit: %s\n", ok ? "OK" : "FAILED");
}

static void test_thread_filtered_breakpoints() {
    printf("\n── Test: Thread-filtered breakpoints ──\n");

    BreakpointManager mgr;
    Breakpoint bp;
    bp.address = 0x6000;
    bp.threadFilter = 1234;
    int id = mgr.add(bp);

    BreakpointHit miss{};
    miss.bpId = id;
    miss.address = bp.address;
    miss.rip = bp.address;
    miss.tid = 4321;
    miss.context.rip = miss.rip;

    BreakpointHit match = miss;
    match.tid = bp.threadFilter;

    bool missed = mgr.recordHit(id, miss);
    bool matched = mgr.recordHit(id, match);

    auto bps = mgr.list();
    auto it = std::find_if(bps.begin(), bps.end(), [id](const Breakpoint& listed) {
        return listed.id == id;
    });

    bool ok = !missed && matched && it != bps.end() && it->hitCount == 1 &&
        mgr.getHits(id).size() == 1 && mgr.getHits(id).front().tid == bp.threadFilter;
    printf("  TID filter: %s\n", ok ? "OK" : "FAILED");
}

static void test_lua_file_aliases() {
    printf("\n── Test: Lua file aliases ──\n");

    auto path = std::filesystem::temp_directory_path() /
        ("cecore-lua-file-" + std::to_string(getpid()) + ".txt");

    LuaEngine lua;
    std::string script =
        "assert(writeFile([[" + path.string() + "]], 'hello'))\n"
        "assert(readFile([[" + path.string() + "]]) == 'hello')\n"
        "assert(getTempDir() ~= nil)\n"
        "assert(getCheatEngineDir() ~= nil)\n";

    auto err = lua.execute(script);
    std::filesystem::remove(path);

    printf("  readFile/writeFile: %s\n", err.empty() ? "OK" : "FAILED");
}

static void test_lua_local_memory() {
    printf("\n── Test: Lua local memory ──\n");

    alignas(uintptr_t) uint8_t local[128] = {};
    auto base = reinterpret_cast<uintptr_t>(local);

    LuaEngine lua;
    std::string script =
        "local base = " + std::to_string(base) + "\n"
        "writeByteLocal(base, 0x2a)\n"
        "assert(readByteLocal(base) == 0x2a)\n"
        "writeSmallIntegerLocal(base + 2, -1234)\n"
        "assert(readSmallIntegerLocal(base + 2) == -1234)\n"
        "writeIntegerLocal(base + 8, 0x12345678)\n"
        "assert(readIntegerLocal(base + 8) == 0x12345678)\n"
        "writeQwordLocal(base + 16, 0x112233445566778)\n"
        "assert(readQwordLocal(base + 16) == 0x112233445566778)\n"
        "writePointerLocal(base + 24, base)\n"
        "assert(readPointerLocal(base + 24) == base)\n"
        "writeFloatLocal(base + 40, 3.5)\n"
        "assert(math.abs(readFloatLocal(base + 40) - 3.5) < 0.001)\n"
        "writeDoubleLocal(base + 48, 9.25)\n"
        "assert(math.abs(readDoubleLocal(base + 48) - 9.25) < 0.001)\n"
        "writeBytesLocal(base + 64, {1, 2, 3, 255})\n"
        "local bytes = readBytesLocal(base + 64, 4)\n"
        "assert(bytes[1] == 1 and bytes[2] == 2 and bytes[3] == 3 and bytes[4] == 255)\n"
        "writeStringLocal(base + 72, 'hello')\n"
        "assert(readStringLocal(base + 72, 16) == 'hello')\n";

    auto err = lua.execute(script);

    printf("  read/write local variants: %s\n", err.empty() ? "OK" : "FAILED");
}

static void test_lua_autoassemble_check() {
    printf("\n── Test: Lua autoAssembleCheck ──\n");

    LuaEngine lua;
    std::string script = R"lua(
local ok, msg = autoAssembleCheck([[
alloc(lua_check_block, 64)
lua_check_block:
db 90
]])
assert(ok == true and msg == nil)
)lua";

    auto err = lua.execute(script);

    printf("  autoAssembleCheck: %s\n", err.empty() ? "OK" : "FAILED");
}

static void test_lua_process_bindings(pid_t pid) {
    printf("\n── Test: Lua process bindings ──\n");

    LuaEngine lua;
    std::string pidText = std::to_string(pid);
    std::string script =
        "local pid = " + pidText + "\n"
        "local list = getProcessList()\n"
        "assert(type(list) == 'table')\n"
        "assert(type(list[pid]) == 'table')\n"
        "assert(list[pid].pid == pid)\n"
        "assert(type(getProcessIDFromProcessName('sleep')) == 'number')\n"
        "assert(openProcess(tostring(pid)) == pid)\n"
        "assert(getOpenedProcessID() == pid)\n"
        "assert(getProcessID() == pid)\n";

    auto err = lua.execute(script);

    printf("  openProcess/getProcessList: %s\n", err.empty() ? "OK" : "FAILED");
}

static void test_lua_memscan() {
    printf("\n── Test: Lua memscan bindings ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  firstScan/nextScan: FAILED\n");
        return;
    }

    auto* target = reinterpret_cast<int32_t*>(page);
    *target = 1111;
    auto base = reinterpret_cast<uintptr_t>(page);

    LinuxProcessHandle proc(getpid());
    LuaEngine lua;
    lua.setProcess(&proc);

    std::string script =
        "local base = " + std::to_string(base) + "\n"
        "local stop = base + " + std::to_string(pageSize) + "\n"
        "local ms = createMemScan()\n"
        "assert(ms:firstScan(" + std::to_string((int)ScanCompare::Exact) + ", " +
            std::to_string((int)ValueType::Int32) + ", '1111', base, stop, 4))\n"
        "assert(ms:getFoundCount() == 1)\n"
        "assert(ms:getAddress(0) == base)\n"
        "writeIntegerLocal(base, 2222)\n"
        "assert(ms:nextScan(" + std::to_string((int)ScanCompare::Exact) + ", " +
            std::to_string((int)ValueType::Int32) + ", '2222', base, stop, 4))\n"
        "assert(ms:getFoundCount() == 1)\n"
        "assert(ms:getAddress(0) == base)\n";

    auto err = lua.execute(script);
    munmap(page, pageSize);

    printf("  firstScan/nextScan: %s\n", err.empty() ? "OK" : "FAILED");
}

static void test_binary_scan_bitmask() {
    printf("\n── Test: Binary scan bitmask ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  bit wildcard match: FAILED\n");
        return;
    }

    auto* bytes = reinterpret_cast<uint8_t*>(page);
    bytes[16] = 0xAC;
    bytes[17] = 0x5A;
    bytes[32] = 0xBC;
    bytes[33] = 0x5A;
    bytes[48] = 0xAC;
    bytes[49] = 0x5B;

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;
    ScanConfig config;
    config.valueType = ValueType::Binary;
    config.compareType = ScanCompare::Exact;
    config.parseBinary("1010???? 01011010");
    config.alignment = 1;
    config.startAddress = reinterpret_cast<uintptr_t>(page);
    config.stopAddress = config.startAddress + pageSize;

    auto result = scanner.firstScan(proc, config);
    bool ok = result.count() == 1 && result.address(0) == config.startAddress + 16;

    munmap(page, pageSize);

    printf("  bit wildcard match: %s\n", ok ? "OK" : "FAILED");
}

static void test_unicode_string_scan() {
    printf("\n── Test: Unicode string scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  UTF-16LE match: FAILED\n");
        return;
    }

    auto* bytes = reinterpret_cast<uint8_t*>(page);
    bytes[24] = 'H';
    bytes[25] = 0;
    bytes[26] = 'i';
    bytes[27] = 0;
    bytes[80] = 'H';
    bytes[81] = 'i';

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;
    ScanConfig config;
    config.valueType = ValueType::UnicodeString;
    config.compareType = ScanCompare::Exact;
    config.stringValue = "Hi";
    config.alignment = 1;
    config.startAddress = reinterpret_cast<uintptr_t>(page);
    config.stopAddress = config.startAddress + pageSize;

    auto result = scanner.firstScan(proc, config);
    bool ok = result.count() == 1 && result.address(0) == config.startAddress + 24;

    munmap(page, pageSize);

    printf("  UTF-16LE match: %s\n", ok ? "OK" : "FAILED");
}

static void test_all_types_scan() {
    printf("\n── Test: All types scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  vtAll numeric match: FAILED\n");
        return;
    }

    std::memset(page, 0x7f, pageSize);
    auto base = reinterpret_cast<uintptr_t>(page);
    auto* bytes = reinterpret_cast<uint8_t*>(page);
    uint8_t byteValue = 42;
    int16_t wordValue = 42;
    int32_t dwordValue = 42;
    int64_t qwordValue = 42;
    float floatValue = 42.0f;
    double doubleValue = 42.0;
    std::memcpy(bytes + 16, &byteValue, sizeof(byteValue));
    std::memcpy(bytes + 32, &wordValue, sizeof(wordValue));
    std::memcpy(bytes + 48, &dwordValue, sizeof(dwordValue));
    std::memcpy(bytes + 64, &qwordValue, sizeof(qwordValue));
    std::memcpy(bytes + 80, &floatValue, sizeof(floatValue));
    std::memcpy(bytes + 96, &doubleValue, sizeof(doubleValue));

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;
    ScanConfig config;
    config.valueType = ValueType::All;
    config.compareType = ScanCompare::Exact;
    config.intValue = 42;
    config.floatValue = 42.0;
    config.alignment = 1;
    config.startAddress = base;
    config.stopAddress = base + pageSize;

    auto result = scanner.firstScan(proc, config);
    auto hasAddress = [&result](uintptr_t address) {
        for (size_t i = 0; i < result.count(); ++i)
            if (result.address(i) == address)
                return true;
        return false;
    };
    bool ok = hasAddress(base + 16) && hasAddress(base + 32) &&
        hasAddress(base + 48) && hasAddress(base + 64) &&
        hasAddress(base + 80) && hasAddress(base + 96);

    munmap(page, pageSize);

    printf("  vtAll numeric match: %s\n", ok ? "OK" : "FAILED");
}

static void test_process_enumeration() {
    printf("\n── Test: Process Enumeration ──\n");
    LinuxProcessEnumerator enumerator;
    auto procs = enumerator.list();
    printf("  Found %zu processes\n", procs.size());
    int shown = 0;
    for (auto& p : procs) {
        if (shown < 5)
            printf("  %8d %s\n", p.pid, p.name.c_str());
        ++shown;
    }
    if (procs.size() > 5)
        printf("  ... and %zu more\n", procs.size() - 5);
}

static void test_process_memory(pid_t pid) {
    printf("\n── Test: Memory Operations (pid=%d) ──\n", pid);
    LinuxProcessHandle proc(pid);

    printf("  is64bit: %s\n", proc.is64bit() ? "yes" : "no");

    // Query regions
    auto regions = proc.queryRegions();
    printf("  Memory regions: %zu\n", regions.size());

    size_t totalReadable = 0;
    for (auto& r : regions) {
        if (r.protection & MemProt::Read)
            totalReadable += r.size;
    }
    printf("  Total readable: %zu bytes (%.1f MB)\n", totalReadable, totalReadable / 1048576.0);

    // Show first 5 regions
    for (size_t i = 0; i < std::min(regions.size(), size_t(5)); ++i) {
        auto& r = regions[i];
        char perms[4] = "---";
        if (r.protection & MemProt::Read)  perms[0] = 'r';
        if (r.protection & MemProt::Write) perms[1] = 'w';
        if (r.protection & MemProt::Exec)  perms[2] = 'x';
        printf("  %016lx-%016lx %s %8zu %s\n",
            r.base, r.base + r.size, perms, r.size, r.path.c_str());
    }

    // Read first readable region
    auto readable = std::find_if(regions.begin(), regions.end(),
        [](const MemoryRegion& r) { return r.protection & MemProt::Read; });

    if (readable != regions.end()) {
        uint8_t buf[64];
        auto result = proc.read(readable->base, buf, sizeof(buf));
        if (result) {
            printf("\n  Read %zu bytes from 0x%lx:\n  ", *result, readable->base);
            for (size_t i = 0; i < std::min(*result, size_t(16)); ++i)
                printf("%02x ", buf[i]);
            printf("\n");
        } else {
            printf("  Read FAILED: %s\n", result.error().message().c_str());
        }
    }

    // Module enumeration
    auto mods = proc.modules();
    printf("\n  Modules: %zu\n", mods.size());
    for (size_t i = 0; i < std::min(mods.size(), size_t(5)); ++i)
        printf("  %016lx %s\n", mods[i].base, mods[i].name.c_str());

    // Thread enumeration
    auto tids = proc.threads();
    printf("\n  Threads: %zu\n", tids.size());
    for (auto& t : tids)
        printf("  tid=%d\n", t.tid);
}

static void test_write_memory(pid_t pid) {
    printf("\n── Test: Memory Write (pid=%d) ──\n", pid);
    LinuxProcessHandle proc(pid);

    auto regions = proc.queryRegions();
    // Find a writable region (heap)
    auto writable = std::find_if(regions.begin(), regions.end(),
        [](const MemoryRegion& r) {
            return (r.protection & MemProt::Read) && (r.protection & MemProt::Write)
                && r.path.find("[heap]") != std::string::npos;
        });

    if (writable == regions.end()) {
        printf("  No writable heap region found\n");
        return;
    }

    uint64_t orig = 0;
    auto rr = proc.read(writable->base, &orig, 8);
    if (!rr) { printf("  Read failed\n"); return; }

    printf("  Original 8 bytes at 0x%lx: %016lx\n", writable->base, orig);

    uint64_t test = 0xDEADBEEFCAFEBABEULL;
    auto wr = proc.write(writable->base, &test, 8);
    if (!wr) { printf("  Write failed: %s\n", wr.error().message().c_str()); return; }

    uint64_t readback = 0;
    proc.read(writable->base, &readback, 8);
    printf("  After write: %016lx %s\n", readback, readback == test ? "OK" : "MISMATCH!");

    // Restore
    proc.write(writable->base, &orig, 8);
}

int main(int argc, char* argv[]) {
    if (getuid() != 0) {
        fprintf(stderr, "WARNING: Not running as root. Some operations may fail.\n");
    }

    pid_t targetPid = 0;

    if (argc > 1) {
        targetPid = atoi(argv[1]);
        printf("Using target PID: %d\n", targetPid);
    } else {
        // Spawn a test process
        targetPid = fork();
        if (targetPid == 0) {
            // Child — just sleep
            execl("/usr/bin/sleep", "sleep", "9999", nullptr);
            _exit(1);
        }
        printf("Spawned test process: sleep 9999 (PID %d)\n", targetPid);
        usleep(200000); // Wait for it to start
    }

    test_cheat_table_json();
    test_autoassembler_unregister_symbol(targetPid);
    test_autoassembler_dealloc(targetPid);
    test_autoassembler_data_directive_widths(targetPid);
    test_autoassembler_nop_fillmem(targetPid);
    test_autoassembler_ds(targetPid);
    test_autoassembler_loadbinary(targetPid);
    test_autoassembler_aobscanmodule(targetPid);
    test_autoassembler_aobscanregion(targetPid);
    test_autoassembler_aobscanall(targetPid);
    test_autoassembler_requires_target(targetPid);
    test_breakpoint_conditions();
    test_one_shot_breakpoints();
    test_thread_filtered_breakpoints();
    test_lua_file_aliases();
    test_lua_local_memory();
    test_lua_autoassemble_check();
    test_lua_process_bindings(targetPid);
    test_lua_memscan();
    test_binary_scan_bitmask();
    test_unicode_string_scan();
    test_all_types_scan();
    test_process_enumeration();
    test_process_memory(targetPid);
    test_write_memory(targetPid);

    // Cleanup spawned process
    if (argc <= 1) {
        kill(targetPid, SIGTERM);
        waitpid(targetPid, nullptr, 0);
        printf("\nKilled test process %d\n", targetPid);
    }

    printf("\nAll tests complete.\n");
    return 0;
}
