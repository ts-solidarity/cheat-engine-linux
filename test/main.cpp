#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "platform/linux/ceserver_client.hpp"
#include "platform/network_compression.hpp"
#include "scanner/pointer_scanner.hpp"
#include "core/autoasm.hpp"
#include "core/ct_file.hpp"
#include "core/trainer.hpp"
#include "analysis/code_analysis.hpp"
#include "analysis/managed_runtime.hpp"
#include "analysis/structure_tools.hpp"
#include "debug/breakpoint_manager.hpp"
#include "debug/stack_trace.hpp"
#include "debug/tracer.hpp"
#include "debug/debug_session.hpp"
#include "debug/gdb_remote.hpp"
#include "scripting/lua_engine.hpp"

#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <csignal>
#include <thread>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

using namespace ce;
using namespace ce::os;

static uint64_t g_traceTargetCounter = 0;

extern "C" __attribute__((noinline)) void cecore_trace_target_tick() {
    ++g_traceTargetCounter;
    asm volatile("nop\nnop\nnop\n" ::: "memory");
}

class FakeProcessHandle final : public ProcessHandle {
public:
    struct Segment {
        MemoryRegion region;
        std::vector<uint8_t> data;
    };

    explicit FakeProcessHandle(std::vector<Segment> segments, std::vector<ModuleInfo> modules)
        : segments_(std::move(segments)), modules_(std::move(modules)) {}

    pid_t pid() const override { return getpid(); }
    bool is64bit() const override { return true; }

    Result<size_t> read(uintptr_t address, void* buffer, size_t size) override {
        for (const auto& segment : segments_) {
            auto start = segment.region.base;
            auto end = start + segment.data.size();
            if (address < start || address >= end) continue;
            auto offset = address - start;
            auto count = std::min<size_t>(size, segment.data.size() - offset);
            std::memcpy(buffer, segment.data.data() + offset, count);
            return count;
        }
        return std::unexpected(std::make_error_code(std::errc::bad_address));
    }

    Result<size_t> write(uintptr_t, const void*, size_t) override {
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    }

    std::vector<MemoryRegion> queryRegions() override {
        std::vector<MemoryRegion> regions;
        for (const auto& segment : segments_) regions.push_back(segment.region);
        return regions;
    }

    std::optional<MemoryRegion> queryRegion(uintptr_t address) override {
        for (const auto& segment : segments_) {
            auto start = segment.region.base;
            auto end = start + segment.region.size;
            if (address >= start && address < end) return segment.region;
        }
        return std::nullopt;
    }

    Result<uintptr_t> allocate(size_t, MemProt, uintptr_t = 0) override {
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    }
    Result<void> free(uintptr_t, size_t) override {
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    }
    Result<void> protect(uintptr_t, size_t, MemProt) override {
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    }
    std::vector<ModuleInfo> modules() override { return modules_; }
    std::vector<ThreadInfo> threads() override { return {}; }

private:
    std::vector<Segment> segments_;
    std::vector<ModuleInfo> modules_;
};

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
    entry.increaseHotkeyKeys = "Ctrl+Up";
    entry.decreaseHotkeyKeys = "Ctrl+Down";
    entry.hotkeyStep = "5";
    table.entries.push_back(entry);

    StructureDefinition structure;
    structure.name = "Player";
    structure.size = 16;
    structure.fields.push_back({"health", 0, ValueType::Int32, 4});
    structure.fields.push_back({"mana", 4, ValueType::Float, 4});
    structure.fields[0].displayMethod = "unsigned";
    structure.fields.push_back({"position", 8, ValueType::ByteArray, 8});
    structure.fields[2].nestedStructure = "Vector2";
    table.structures.push_back(structure);

    auto jsonPath = std::filesystem::temp_directory_path() /
        ("cecore-table-" + std::to_string(getpid()) + ".json");
    auto xmlPath = std::filesystem::temp_directory_path() /
        ("cecore-table-" + std::to_string(getpid()) + ".CT");
    auto protectedPath = std::filesystem::temp_directory_path() /
        ("cecore-table-" + std::to_string(getpid()) + ".CETRAINER");

    if (!table.saveJson(jsonPath.string()) || !table.save(xmlPath.string()) ||
        !table.saveProtected(protectedPath.string(), "secret")) {
        printf("  Save FAILED\n");
        return;
    }

    auto matchesTable = [&table, &entry](const CheatTable& loaded) {
        return loaded.gameName == table.gameName &&
            loaded.gameVersion == table.gameVersion &&
            loaded.author == table.author &&
            loaded.comment == table.comment &&
            loaded.luaScript == table.luaScript &&
            loaded.structures.size() == 1 &&
            loaded.structures[0].name == "Player" &&
            loaded.structures[0].size == 16 &&
            loaded.structures[0].fields.size() == 3 &&
            loaded.structures[0].fields[0].name == "health" &&
            loaded.structures[0].fields[0].offset == 0 &&
            loaded.structures[0].fields[0].type == ValueType::Int32 &&
            loaded.structures[0].fields[0].displayMethod == "unsigned" &&
            loaded.structures[0].fields[1].name == "mana" &&
            loaded.structures[0].fields[1].offset == 4 &&
            loaded.structures[0].fields[1].type == ValueType::Float &&
            loaded.structures[0].fields[2].name == "position" &&
            loaded.structures[0].fields[2].nestedStructure == "Vector2" &&
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
            loaded.entries[0].hotkeyKeys == entry.hotkeyKeys &&
            loaded.entries[0].increaseHotkeyKeys == entry.increaseHotkeyKeys &&
            loaded.entries[0].decreaseHotkeyKeys == entry.decreaseHotkeyKeys &&
            loaded.entries[0].hotkeyStep == entry.hotkeyStep;
    };

    CheatTable jsonLoaded;
    bool jsonOk = jsonLoaded.loadJson(jsonPath.string()) && matchesTable(jsonLoaded);
    CheatTable xmlLoaded;
    bool xmlOk = xmlLoaded.load(xmlPath.string()) && matchesTable(xmlLoaded);
    std::ifstream xmlFile(xmlPath);
    std::string xmlText((std::istreambuf_iterator<char>(xmlFile)), {});
    bool xmlTypeNamesOk =
        xmlText.find("<VariableType>4 Bytes</VariableType>") != std::string::npos &&
        xmlText.find("<Type>4 Bytes</Type>") != std::string::npos &&
        xmlText.find("<Type>Float</Type>") != std::string::npos &&
        xmlText.find("<Type>Array of byte</Type>") != std::string::npos;
    CheatTable protectedLoaded;
    bool protectedOk = protectedLoaded.loadProtected(protectedPath.string(), "secret") &&
        matchesTable(protectedLoaded);
    CheatTable wrongPassword;
    bool wrongPasswordOk = !wrongPassword.loadProtected(protectedPath.string(), "wrong");
    std::filesystem::remove(jsonPath);
    std::filesystem::remove(xmlPath);
    std::filesystem::remove(protectedPath);

    printf("  JSON round trip: %s\n", jsonOk ? "OK" : "FAILED");
    printf("  CT XML round trip: %s\n", xmlOk ? "OK" : "FAILED");
    printf("  CT XML CE type names: %s\n", xmlTypeNamesOk ? "OK" : "FAILED");
    printf("  CETRAINER protected round trip: %s\n", (protectedOk && wrongPasswordOk) ? "OK" : "FAILED");
}

static void test_trainer_generation() {
    printf("\n── Test: Trainer Generation ──\n");

    CheatTable table;
    table.gameName = "Trainer \"Smoke\"\nGame";
    table.author = "cecore";
    table.luaScript = "print('table trainer lua')\n";

    CheatEntry entry;
    entry.description = "Health \"current\"\nline";
    entry.address = 0x12345678;
    entry.type = ValueType::Int32;
    entry.value = "1337";
    entry.hotkeyKeys = "Ctrl+H";
    entry.luaScript = "print('entry trainer lua')\n";
    entry.autoAsmScript = "[ENABLE]\nnop\n";
    table.entries.push_back(entry);

    TrainerGenerator generator;
    auto source = generator.generateSource(table);
    bool sourceOk =
        source.find("Trainer \\\"Smoke\\\"\\nGame") != std::string::npos &&
        source.find("Health \\\"current\\\"\\nline") != std::string::npos &&
        source.find("#include <sys/select.h>") != std::string::npos &&
        source.find("find_process_by_name") != std::string::npos &&
        source.find("else target_pid = find_process_by_name") != std::string::npos &&
        source.find("hotkey_matches") != std::string::npos &&
        source.find("\"Ctrl+H\"") != std::string::npos &&
        source.find("print_trainer_ui") != std::string::npos &&
        source.find("[%c]") != std::string::npos &&
        source.find("embedded_table_lua") != std::string::npos &&
        source.find("entry trainer lua") != std::string::npos &&
        source.find("[ENABLE]\\nnop\\n") != std::string::npos;

    auto outputPath = std::filesystem::temp_directory_path() /
        ("cecore-trainer-" + std::to_string(getpid()));
    auto error = generator.generateBinary(table, outputPath.string());
    bool binaryOk = error.empty() && std::filesystem::exists(outputPath);

    std::filesystem::remove(outputPath);
    std::filesystem::remove(outputPath.string() + ".c");

    printf("  source escaping: %s\n", sourceOk ? "OK" : "FAILED");
    printf("  binary compile: %s\n", binaryOk ? "OK" : "FAILED");
    if (!error.empty())
        printf("    error: %s\n", error.c_str());
}

static void test_code_analysis_references() {
    printf("\n── Test: Code Analysis References ──\n");

    const uintptr_t codeBase = 0x1000;
    const uintptr_t stringBase = 0x2000;
    const uintptr_t callTarget = 0x3000;

    std::vector<uint8_t> code = {
        0x48, 0x8d, 0x05, 0xf9, 0x0f, 0x00, 0x00, // lea rax, [rip + 0xff9] -> 0x2000
        0xe8, 0xf4, 0x1f, 0x00, 0x00,             // call 0x3000
        0xeb, 0x01,                                     // jmp 0x100f
        0xc3                                            // ret
    };
    code.insert(code.end(), 20, 0x00);
    std::vector<uint8_t> text = {'h', 'e', 'l', 'l', 'o', ' ', 'c', 'e', 0};

    ModuleInfo module{codeBase, 0x1000, "fake.so", "/tmp/fake.so", true};
    FakeProcessHandle proc({
        {{codeBase, code.size(), MemProt::ReadExec, MemType::Image, MemState::Committed, module.path}, code},
        {{stringBase, text.size(), MemProt::Read, MemType::Image, MemState::Committed, module.path}, text},
    }, {module});

    CodeAnalyzer analyzer;
    auto strings = analyzer.findReferencedStrings(proc, module);
    auto functions = analyzer.findReferencedFunctions(proc, module);
    auto functionSummary = analyzer.enumerateFunctions(proc, module);
    auto callGraph = analyzer.buildCallGraph(proc, module);
    auto jumps = analyzer.findJumps(proc, module);
    auto ripRelative = analyzer.findRipRelativeInstructions(proc, module);
    auto assembly = analyzer.findAssemblyPattern(proc, module, "ret");
    auto caves = analyzer.findCodeCaves(proc, module, 16);

    bool stringOk = strings.size() == 1 && strings[0].address == codeBase &&
        strings[0].target == stringBase && strings[0].text == "hello ce";
    bool functionOk = functions.size() == 1 && functions[0].address == codeBase + 7 &&
        functions[0].target == callTarget;
    bool functionSummaryOk = functionSummary.size() == 1 &&
        functionSummary[0].address == callTarget &&
        functionSummary[0].references == 1;
    bool callGraphOk = callGraph.size() == 1 &&
        callGraph[0].caller == codeBase &&
        callGraph[0].callee == callTarget &&
        callGraph[0].callSite == codeBase + 7;
    bool jumpsOk = jumps.size() == 1 && jumps[0].address == codeBase + 12 &&
        jumps[0].target == codeBase + 15;
    bool ripOk = ripRelative.size() == 1 && ripRelative[0].address == codeBase &&
        ripRelative[0].target == stringBase;
    bool assemblyOk = assembly.size() == 1 && assembly[0].address == codeBase + 14;
    bool cavesOk = caves.size() == 1 && caves[0].address == codeBase + 15 && caves[0].size == 20;

    printf("  Referenced strings: %s\n", stringOk ? "OK" : "FAILED");
    printf("  Referenced functions: %s\n", functionOk ? "OK" : "FAILED");
    printf("  Function enumeration: %s\n", functionSummaryOk ? "OK" : "FAILED");
    printf("  Call graph: %s\n", callGraphOk ? "OK" : "FAILED");
    printf("  Jump detection: %s\n", jumpsOk ? "OK" : "FAILED");
    printf("  RIP-relative instructions: %s\n", ripOk ? "OK" : "FAILED");
    printf("  Assembly pattern scan: %s\n", assemblyOk ? "OK" : "FAILED");
    printf("  Code caves: %s\n", cavesOk ? "OK" : "FAILED");
}

static void test_managed_runtime_detection() {
    printf("\n── Test: Managed runtime detection ──\n");

    FakeProcessHandle proc({}, {
        {0x100000, 0x20000, "libmonosgen-2.0.so", "/usr/lib/libmonosgen-2.0.so", true},
        {0x200000, 0x30000, "libclrjit.so", "/opt/dotnet/shared/Microsoft.NETCore.App/libclrjit.so", true},
        {0x300000, 0x10000, "libnative.so", "/tmp/libnative.so", true},
    });
    auto runtimes = detectManagedRuntimes(proc);

    FakeProcessHandle nativeOnly({}, {
        {0x400000, 0x10000, "libc.so.6", "/usr/lib/libc.so.6", true},
    });
    auto none = detectManagedRuntimes(nativeOnly);

    bool monoOk = std::any_of(runtimes.begin(), runtimes.end(), [](const ManagedRuntimeInfo& info) {
        return info.kind == ManagedRuntimeKind::Mono &&
            info.name == "Mono" &&
            info.moduleName == "libmonosgen-2.0.so";
    });
    bool coreClrOk = std::any_of(runtimes.begin(), runtimes.end(), [](const ManagedRuntimeInfo& info) {
        return info.kind == ManagedRuntimeKind::CoreCLR &&
            info.name == "CoreCLR" &&
            info.moduleName == "libclrjit.so";
    });

    printf("  Mono/CoreCLR modules: %s\n",
        (monoOk && coreClrOk && none.empty()) ? "OK" : "FAILED");
}

static void test_managed_object_enumeration() {
    printf("\n── Test: Managed object enumeration ──\n");

    constexpr uintptr_t metadataBase = 0x500000;
    constexpr uintptr_t heapBase = 0x800000;
    std::vector<uint8_t> metadata(0x200, 0);
    std::vector<uint8_t> heap(0x200, 0);

    uintptr_t playerType = metadataBase + 0x40;
    uintptr_t inventoryType = metadataBase + 0x90;
    uintptr_t nativePointer = 0x12345678;
    std::memcpy(heap.data() + 0x20, &playerType, sizeof(playerType));
    std::memcpy(heap.data() + 0x80, &inventoryType, sizeof(inventoryType));
    std::memcpy(heap.data() + 0xc0, &nativePointer, sizeof(nativePointer));

    FakeProcessHandle proc({
        {{metadataBase, metadata.size(), MemProt::Read, MemType::Image, MemState::Committed, "/opt/dotnet/System.Private.CoreLib.dll"}, metadata},
        {{heapBase, heap.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[managed heap]"}, heap},
    }, {
        {metadataBase, metadata.size(), "System.Private.CoreLib.dll", "/opt/dotnet/System.Private.CoreLib.dll", true},
    });

    ManagedObjectEnumerationConfig config;
    config.runtimeKind = ManagedRuntimeKind::CoreCLR;
    auto objects = enumerateManagedObjects(proc, config);

    config.heapStart = heapBase + 0x70;
    config.heapEnd = heapBase + 0x100;
    config.maxObjects = 1;
    auto bounded = enumerateManagedObjects(proc, config);

    bool playerOk = std::any_of(objects.begin(), objects.end(), [&](const ManagedObjectInfo& object) {
        return object.address == heapBase + 0x20 &&
            object.typeHandle == playerType &&
            object.runtimeKind == ManagedRuntimeKind::CoreCLR &&
            object.regionPath == "[managed heap]";
    });
    bool inventoryOk = std::any_of(objects.begin(), objects.end(), [&](const ManagedObjectInfo& object) {
        return object.address == heapBase + 0x80 && object.typeHandle == inventoryType;
    });
    bool boundedOk = bounded.size() == 1 &&
        bounded.front().address == heapBase + 0x80 &&
        bounded.front().typeHandle == inventoryType;

    printf("  object headers: %s\n",
        (objects.size() == 2 && playerOk && inventoryOk && boundedOk) ? "OK" : "FAILED");
}

static void test_managed_type_extraction() {
    printf("\n── Test: Managed type extraction ──\n");

    constexpr uintptr_t metadataBase = 0x510000;
    constexpr uintptr_t heapBase = 0x810000;
    std::vector<uint8_t> metadata(0x300, 0);
    std::vector<uint8_t> heap(0x200, 0);

    uintptr_t playerType = metadataBase + 0x40;
    uintptr_t inventoryType = metadataBase + 0x80;
    uintptr_t playerName = metadataBase + 0x140;
    uintptr_t playerNamespace = metadataBase + 0x180;
    uintptr_t inventoryName = metadataBase + 0x1c0;
    uintptr_t inventoryNamespace = metadataBase + 0x200;

    std::memcpy(metadata.data() + 0x40, &playerName, sizeof(playerName));
    std::memcpy(metadata.data() + 0x48, &playerNamespace, sizeof(playerNamespace));
    std::memcpy(metadata.data() + 0x80, &inventoryName, sizeof(inventoryName));
    std::memcpy(metadata.data() + 0x88, &inventoryNamespace, sizeof(inventoryNamespace));
    std::memcpy(metadata.data() + 0x140, "Player", sizeof("Player"));
    std::memcpy(metadata.data() + 0x180, "Game.Entities", sizeof("Game.Entities"));
    std::memcpy(metadata.data() + 0x1c0, "Inventory", sizeof("Inventory"));
    std::memcpy(metadata.data() + 0x200, "Game.Items", sizeof("Game.Items"));

    std::memcpy(heap.data() + 0x20, &playerType, sizeof(playerType));
    std::memcpy(heap.data() + 0x80, &inventoryType, sizeof(inventoryType));
    std::memcpy(heap.data() + 0xa0, &playerType, sizeof(playerType));

    FakeProcessHandle proc({
        {{metadataBase, metadata.size(), MemProt::Read, MemType::Image, MemState::Committed, "/opt/dotnet/System.Private.CoreLib.dll"}, metadata},
        {{heapBase, heap.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[managed heap]"}, heap},
    }, {
        {metadataBase, metadata.size(), "System.Private.CoreLib.dll", "/opt/dotnet/System.Private.CoreLib.dll", true},
    });

    ManagedObjectEnumerationConfig objectConfig;
    objectConfig.runtimeKind = ManagedRuntimeKind::CoreCLR;
    auto objects = enumerateManagedObjects(proc, objectConfig);

    ManagedTypeExtractionConfig typeConfig;
    typeConfig.runtimeKind = ManagedRuntimeKind::CoreCLR;
    auto types = extractManagedObjectTypes(proc, objects, typeConfig);

    bool playerOk = std::any_of(types.begin(), types.end(), [&](const ManagedTypeInfo& type) {
        return type.typeHandle == playerType &&
            type.name == "Player" &&
            type.namespaceName == "Game.Entities" &&
            type.runtimeKind == ManagedRuntimeKind::CoreCLR;
    });
    bool inventoryOk = std::any_of(types.begin(), types.end(), [&](const ManagedTypeInfo& type) {
        return type.typeHandle == inventoryType &&
            type.name == "Inventory" &&
            type.namespaceName == "Game.Items";
    });

    printf("  type names: %s\n",
        (objects.size() == 3 && types.size() == 2 && playerOk && inventoryOk) ? "OK" : "FAILED");
}

static void test_gdb_remote_client() {
    printf("\n── Test: GDB remote client ──\n");

    auto checksum = [](const std::string& payload) {
        uint8_t sum = 0;
        for (unsigned char c : payload)
            sum = static_cast<uint8_t>(sum + c);
        return sum;
    };
    auto sendPacket = [&](int fd, const std::string& payload) {
        char suffix[4];
        std::snprintf(suffix, sizeof(suffix), "#%02x", checksum(payload));
        std::string packet = "$" + payload + suffix;
        ::send(fd, packet.data(), packet.size(), 0);
        char ack = 0;
        ::recv(fd, &ack, 1, MSG_WAITALL);
    };
    auto readPacket = [](int fd) {
        char c = 0;
        do {
            if (::recv(fd, &c, 1, MSG_WAITALL) != 1)
                return std::string{};
        } while (c != '$');

        std::string payload;
        while (::recv(fd, &c, 1, MSG_WAITALL) == 1 && c != '#')
            payload.push_back(c);
        char ignored[2] = {};
        ::recv(fd, ignored, 2, MSG_WAITALL);
        ::send(fd, "+", 1, 0);
        return payload;
    };

    int server = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bool setupOk = server >= 0 &&
        ::bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
        ::listen(server, 1) == 0;
    socklen_t addrLen = sizeof(addr);
    if (setupOk)
        setupOk = ::getsockname(server, reinterpret_cast<sockaddr*>(&addr), &addrLen) == 0;

    if (!setupOk) {
        if (server >= 0) ::close(server);
        printf("  packet exchange: FAILED\n");
        return;
    }

    bool serverOk = false;
    std::thread stub([&]() {
        int client = ::accept(server, nullptr, nullptr);
        if (client < 0)
            return;

        auto first = readPacket(client);
        sendPacket(client, "01020304");
        auto second = readPacket(client);
        sendPacket(client, "11223344");

        serverOk = first == "g" && second == "m1000,4";
        ::close(client);
    });

    GdbRemoteClient client;
    std::string error;
    bool connected = client.connectTcp("127.0.0.1", ntohs(addr.sin_port), error);
    std::expected<std::string, std::string> regs = std::unexpected(error);
    std::expected<std::vector<uint8_t>, std::string> mem = std::unexpected(error);
    if (connected) {
        regs = client.readRegisters();
        mem = client.readMemory(0x1000, 4);
    }
    client.close();
    stub.join();
    ::close(server);

    bool ok = connected &&
        regs && *regs == "01020304" &&
        mem && *mem == std::vector<uint8_t>({0x11, 0x22, 0x33, 0x44}) &&
        serverOk;
    printf("  packet exchange: %s\n", ok ? "OK" : "FAILED");
}

static void test_ceserver_client() {
    printf("\n── Test: ceserver TCP client ──\n");

    int server = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bool setupOk = server >= 0 &&
        ::bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
        ::listen(server, 1) == 0;
    socklen_t addrLen = sizeof(addr);
    if (setupOk)
        setupOk = ::getsockname(server, reinterpret_cast<sockaddr*>(&addr), &addrLen) == 0;

    if (!setupOk) {
        if (server >= 0) ::close(server);
        printf("  version handshake: FAILED\n");
        return;
    }

    bool serverOk = false;
    std::thread stub([&]() {
        int client = ::accept(server, nullptr, nullptr);
        if (client < 0)
            return;

        uint8_t command = 0xff;
        ::recv(client, &command, sizeof(command), MSG_WAITALL);
        int32_t protocol = 6;
        const std::string version = "CHEATENGINE Network 2.3";
        uint8_t size = static_cast<uint8_t>(version.size());
        ::send(client, &protocol, sizeof(protocol), 0);
        ::send(client, &size, sizeof(size), 0);
        ::send(client, version.data(), version.size(), 0);
        serverOk = command == 0;
        ::close(client);
    });

    CEServerClient client;
    std::string error;
    bool connected = client.connectTcp("127.0.0.1", ntohs(addr.sin_port), error);
    std::expected<CEServerVersionInfo, std::string> version = std::unexpected(error);
    if (connected)
        version = client.getVersion();
    client.close();
    stub.join();
    ::close(server);

    bool ok = connected &&
        version &&
        version->protocolVersion == 6 &&
        version->versionString == "CHEATENGINE Network 2.3" &&
        serverOk;
    printf("  version handshake: %s\n", ok ? "OK" : "FAILED");
}

static void test_network_compression() {
    printf("\n── Test: Network compression ──\n");

    std::vector<uint8_t> payload;
    payload.reserve(4096);
    for (int i = 0; i < 4096; ++i)
        payload.push_back(static_cast<uint8_t>((i * 17) & 0xff));

    auto compressed = ce::net::compressPayload(payload, 9);
    std::expected<std::vector<uint8_t>, std::string> decompressed =
        std::unexpected(compressed ? "" : compressed.error());
    if (compressed)
        decompressed = ce::net::decompressPayload(*compressed, payload.size());

    auto badLevel = ce::net::compressPayload(payload, 99);
    std::expected<std::vector<uint8_t>, std::string> wrongSize =
        std::unexpected(compressed ? "" : compressed.error());
    if (compressed)
        wrongSize = ce::net::decompressPayload(*compressed, payload.size() + 1);

    bool ok = compressed &&
        decompressed &&
        *decompressed == payload &&
        !badLevel &&
        !wrongSize;
    printf("  zlib round trip: %s\n", ok ? "OK" : "FAILED");
}

static void test_distributed_pointer_scan() {
    printf("\n── Test: Distributed pointer scan ──\n");

    constexpr uintptr_t moduleBase = 0x400000;
    constexpr uintptr_t heapBase = 0x700000;
    constexpr uintptr_t target = heapBase + 0x80;
    std::vector<uint8_t> module(0x100, 0);
    std::vector<uint8_t> heap(0x100, 0);

    uintptr_t heapPointer = target - 0x20;
    uintptr_t staticPointer = heapBase + 0x20;
    std::memcpy(heap.data() + 0x20, &heapPointer, sizeof(heapPointer));
    std::memcpy(module.data() + 0x10, &staticPointer, sizeof(staticPointer));

    FakeProcessHandle proc({
        {{moduleBase, module.size(), MemProt::Read, MemType::Image, MemState::Committed, "/tmp/game"}, module},
        {{heapBase, heap.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, heap},
    }, {
        {moduleBase, module.size(), "game", "/tmp/game", true},
    });

    PointerScanConfig config;
    config.targetAddress = target;
    config.maxDepth = 3;
    config.maxOffset = 0x100;

    PointerScanner fullScanner;
    auto full = fullScanner.scan(proc, config);

    std::vector<PointerPath> merged;
    for (auto shardConfig : makePointerScanShards(config, 2)) {
        PointerScanner shardScanner;
        auto shard = shardScanner.scan(proc, shardConfig);
        merged.insert(merged.end(), shard.begin(), shard.end());
    }

    auto hasExpectedPath = [&](const std::vector<PointerPath>& paths) {
        return std::any_of(paths.begin(), paths.end(), [](const PointerPath& path) {
            return path.module == "game" &&
                path.baseOffset == 0x10 &&
                path.offsets == std::vector<int32_t>({0, 0x20});
        });
    };

    bool ok = hasExpectedPath(full) &&
        hasExpectedPath(merged) &&
        merged.size() == full.size();
    printf("  shard merge: %s\n", ok ? "OK" : "FAILED");
}

static void test_stack_trace_frame_walk() {
    printf("\n── Test: Stack trace frame walk ──\n");

    const uintptr_t stackBase = 0x70000000;
    const uintptr_t rbp0 = stackBase + 0x100;
    const uintptr_t rbp1 = stackBase + 0x140;
    std::vector<uint8_t> stack(0x1000, 0);

    auto writePtr = [&](uintptr_t address, uintptr_t value) {
        std::memcpy(stack.data() + (address - stackBase), &value, sizeof(value));
    };
    writePtr(rbp0, rbp1);
    writePtr(rbp0 + sizeof(uintptr_t), 0x401100);
    writePtr(rbp1, 0);
    writePtr(rbp1 + sizeof(uintptr_t), 0x401200);

    FakeProcessHandle proc({
        {{stackBase, stack.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[stack]"}, stack},
    }, {});

    CpuContext context{};
    context.rip = 0x401000;
    context.rsp = stackBase + 0x80;
    context.rbp = rbp0;

    auto frames = buildStackTrace(proc, context);
    bool ok = frames.size() == 3 &&
        frames[0].instructionPointer == 0x401000 &&
        frames[1].instructionPointer == 0x401100 &&
        frames[1].framePointer == rbp0 &&
        frames[2].instructionPointer == 0x401200 &&
        frames[2].framePointer == rbp1;

    printf("  frame pointer walk: %s\n", ok ? "OK" : "FAILED");
}

static void test_break_and_trace() {
    printf("\n── Test: Break and trace ──\n");

    pid_t child = fork();
    if (child == 0) {
        while (true)
            cecore_trace_target_tick();
        _exit(0);
    }
    if (child < 0) {
        printf("  break and trace: FAILED\n");
        return;
    }

    usleep(50000);

    LinuxProcessHandle proc(child);
    LinuxDebugger dbg;
    Tracer tracer;
    TraceConfig config;
    config.startAddress = reinterpret_cast<uintptr_t>(&cecore_trace_target_tick);
    config.maxSteps = 8;

    auto entries = tracer.trace(proc, dbg, config);
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);

    bool hitStart = !entries.empty() && entries[0].address == config.startAddress;
    bool countOk = entries.size() == static_cast<size_t>(config.maxSteps);
    bool decoded = std::any_of(entries.begin(), entries.end(), [](const TraceEntry& entry) {
        return entry.instruction != "??";
    });

    printf("  break and trace: %s\n", (hitStart && countOk && decoded) ? "OK" : "FAILED");
}

static void test_exception_breakpoint() {
    printf("\n── Test: Exception breakpoints ──\n");

    int fds[2];
    if (pipe(fds) != 0) {
        printf("  SIGSEGV exception breakpoint: FAILED\n");
        return;
    }

    pid_t child = fork();
    if (child == 0) {
        close(fds[1]);
        char token = 0;
        (void)read(fds[0], &token, 1);
        close(fds[0]);
        volatile int* bad = reinterpret_cast<volatile int*>(uintptr_t{0x1});
        (void)*bad;
        _exit(0);
    }

    close(fds[0]);
    if (child < 0) {
        close(fds[1]);
        printf("  SIGSEGV exception breakpoint: FAILED\n");
        return;
    }

    LinuxProcessHandle proc(child);
    DebugSession session;
    std::atomic<bool> hit{false};
    std::atomic<int> signal{0};
    session.setEventCallback([&](const DebugEvent& event) {
        if (event.type == DebugEventType::ExceptionBreakpointHit) {
            hit.store(true);
            signal.store(event.signal);
        }
    });
    session.addExceptionBreakpoint(SIGSEGV);

    bool attached = session.attach(child, &proc);
    write(fds[1], "x", 1);
    close(fds[1]);
    if (attached)
        session.continueExecution();

    for (int i = 0; i < 100 && !hit.load(); ++i)
        usleep(10000);

    if (session.isAttached())
        session.detach();
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);

    printf("  SIGSEGV exception breakpoint: %s\n",
        (attached && hit.load() && signal.load() == SIGSEGV) ? "OK" : "FAILED");
}

static void test_structure_tools() {
    printf("\n── Test: Structure tools ──\n");

    StructureDefinition structure;
    structure.name = "Player State";
    structure.size = 24;
    structure.fields.push_back({"health", 0, ValueType::Int32, 4});
    structure.fields.push_back({"mana value", 4, ValueType::Float, 4});
    structure.fields.push_back({"target", 16, ValueType::Pointer, sizeof(uintptr_t)});
    structure.fields.push_back({"coords", 8, ValueType::ByteArray, 8});
    structure.fields[0].displayMethod = "hex";
    structure.fields[1].displayMethod = "float";
    structure.fields[3].nestedStructure = "Vector2";

    auto path = std::filesystem::temp_directory_path() /
        ("cecore-structure-" + std::to_string(getpid()) + ".json");
    bool saveOk = saveStructureTemplate(structure, path.string());
    auto loaded = loadStructureTemplate(path.string());
    std::filesystem::remove(path);

    auto cpp = generateCppStruct(structure);
    bool loadOk = loaded &&
        loaded->name == structure.name &&
        loaded->size == structure.size &&
        loaded->fields.size() == structure.fields.size() &&
        loaded->fields[1].name == "mana value" &&
        loaded->fields[0].displayMethod == "hex" &&
        loaded->fields[2].type == ValueType::Pointer &&
        loaded->fields[3].nestedStructure == "Vector2";
    bool cppOk = cpp.find("struct Player_State") != std::string::npos &&
        cpp.find("int32_t health; // 0x0") != std::string::npos &&
        cpp.find("float mana_value; // 0x4") != std::string::npos &&
        cpp.find("Vector2 coords; // 0x8") != std::string::npos &&
        cpp.find("uintptr_t target; // 0x10") != std::string::npos;

    std::vector<uint8_t> before(24, 0);
    std::vector<uint8_t> after = before;
    int32_t oldHealth = 0x11223344;
    int32_t newHealth = 0x55667788;
    float mana = 12.5f;
    std::memcpy(before.data(), &oldHealth, sizeof(oldHealth));
    std::memcpy(after.data(), &newHealth, sizeof(newHealth));
    std::memcpy(before.data() + 4, &mana, sizeof(mana));
    std::memcpy(after.data() + 4, &mana, sizeof(mana));
    auto diffs = compareStructureSnapshots(structure, before, after);
    auto hasDiff = [&](const std::string& name, bool changed) {
        return std::any_of(diffs.begin(), diffs.end(), [&](const StructureFieldDiff& diff) {
            return diff.name == name && diff.changed == changed;
        });
    };
    bool diffOk = diffs.size() == 4 &&
        hasDiff("health", true) &&
        hasDiff("mana value", false) &&
        hasDiff("target", false) &&
        hasDiff("coords", false);

    auto detected = autoDetectStructureFields(before, after);
    bool detectOk = detected.size() == 2 &&
        detected[0].offset == 0 && detected[0].size == 4 &&
        detected[0].changed && detected[0].suggestedType == ValueType::Int32 &&
        detected[1].offset == 4 && detected[1].size == 20 &&
        !detected[1].changed;

    const uintptr_t rootBase = 0x80000000;
    const uintptr_t nodeA = rootBase + 0x100;
    const uintptr_t nodeB = rootBase + 0x200;
    std::vector<uint8_t> memory(0x1000, 0);
    std::memcpy(memory.data() + 16, &nodeA, sizeof(nodeA));
    std::memcpy(memory.data() + 0x100, &nodeB, sizeof(nodeB));
    FakeProcessHandle proc({
        {{rootBase, memory.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[structure]"}, memory},
    }, {});
    auto chains = followStructurePointers(proc, rootBase, structure, 3);
    bool pointerOk = chains.size() == 1 &&
        chains[0].fieldName == "target" &&
        chains[0].fieldOffset == 16 &&
        chains[0].addresses.size() == 2 &&
        chains[0].addresses[0] == nodeA &&
        chains[0].addresses[1] == nodeB;

    bool displayOk = formatStructureFieldValue(structure.fields[0], after) == "88 77 66 55" &&
        formatStructureFieldValue(structure.fields[1], after).find("12.5") == 0 &&
        formatStructureFieldValue(structure.fields[2], memory).find("0x") == 0;

    printf("  template save/load: %s\n", (saveOk && loadOk) ? "OK" : "FAILED");
    printf("  C++ struct export: %s\n", cppOk ? "OK" : "FAILED");
    printf("  snapshot comparison: %s\n", diffOk ? "OK" : "FAILED");
    printf("  changed field detection: %s\n", detectOk ? "OK" : "FAILED");
    printf("  pointer chain following: %s\n", pointerOk ? "OK" : "FAILED");
    printf("  custom field display: %s\n", displayOk ? "OK" : "FAILED");
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

static void test_autoassembler_forward_labels(pid_t pid) {
    printf("\n── Test: AutoAssembler forward labels ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;

    auto result = aa.execute(proc,
        "[ENABLE]\n"
        "alloc(forwardblock, 512)\n"
        "label(farreturn)\n"
        "registersymbol(forwardblock,farreturn)\n"
        "forwardblock:\n"
        "jmp farreturn\n"
        "nop 200\n"
        "farreturn:\n"
        "ret\n");

    uintptr_t block = aa.resolveSymbol("forwardblock");
    uintptr_t farreturn = aa.resolveSymbol("farreturn");
    uint8_t firstByte = 0;
    uint8_t returnByte = 0;
    if (block)
        proc.read(block, &firstByte, sizeof(firstByte));
    if (farreturn)
        proc.read(farreturn, &returnByte, sizeof(returnByte));

    bool ok = result.success &&
        block != 0 &&
        farreturn == block + 205 &&
        firstByte == 0xe9 &&
        returnByte == 0xc3;

    aa.disable(proc, "", result.disableInfo);
    printf("  forward label sizing: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_create_thread(pid_t pid) {
    printf("\n── Test: AutoAssembler createthread ──\n");

    LinuxProcessHandle proc(pid);

    AutoAssembler waitedAssembler;
    auto waited = waitedAssembler.execute(proc,
        "[ENABLE]\n"
        "alloc(waitcode, 512)\n"
        "alloc(waitresult, 8)\n"
        "registersymbol(waitresult)\n"
        "waitresult:\n"
        "dd 0\n"
        "waitcode:\n"
        "mov rax, waitresult\n"
        "mov dword [rax], 0x11223344\n"
        "xor eax, eax\n"
        "ret\n"
        "createthreadandwait(waitcode, 2000)\n");

    uint32_t waitedValue = 0;
    auto waitResultAddr = waitedAssembler.resolveSymbol("waitresult");
    if (waitResultAddr)
        proc.read(waitResultAddr, &waitedValue, sizeof(waitedValue));

    AutoAssembler asyncAssembler;
    auto async = asyncAssembler.execute(proc,
        "[ENABLE]\n"
        "alloc(asynccode, 512)\n"
        "alloc(asyncresult, 8)\n"
        "registersymbol(asyncresult)\n"
        "asyncresult:\n"
        "dd 0\n"
        "asynccode:\n"
        "mov rax, asyncresult\n"
        "mov dword [rax], 0x55667788\n"
        "xor eax, eax\n"
        "ret\n"
        "createthread(asynccode)\n");

    uint32_t asyncValue = 0;
    auto asyncResultAddr = asyncAssembler.resolveSymbol("asyncresult");
    for (int i = 0; i < 100 && asyncResultAddr; ++i) {
        proc.read(asyncResultAddr, &asyncValue, sizeof(asyncValue));
        if (asyncValue == 0x55667788)
            break;
        usleep(10000);
    }

    bool ok = waited.success && waitedValue == 0x11223344 &&
        async.success && asyncValue == 0x55667788;

    waitedAssembler.disable(proc, "", waited.disableInfo);
    asyncAssembler.disable(proc, "", async.disableInfo);
    printf("  createthread/andwait: %s\n", ok ? "OK" : "FAILED");
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

static void test_autoassembler_custom_commands(pid_t pid) {
    printf("\n── Test: AutoAssembler custom commands ──\n");

    LinuxProcessHandle proc(pid);
    auto allocResult = proc.allocate(4096, MemProt::All);
    if (!allocResult) {
        printf("  custom commands: FAILED\n");
        return;
    }
    uintptr_t addr = *allocResult;

    AutoAssembler aa;
    aa.registerCommand("emitbytes", [](const std::string& args,
        std::vector<std::string>& outputLines, std::vector<std::string>& log, std::string&) {
        outputLines.push_back("db " + args);
        log.push_back("custom emitbytes");
        return true;
    });
    aa.registerCommand("emitnops", [](const std::string& args,
        std::vector<std::string>& outputLines, std::vector<std::string>&, std::string&) {
        outputLines.push_back("nop " + args);
        return true;
    });

    char script[256];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "%lx:\n"
        "EMITBYTES(2A, 2B)\n"
        "emitnops 2\n",
        addr);

    auto result = aa.execute(proc, script);
    uint8_t actual[4] = {};
    proc.read(addr, actual, sizeof(actual));
    const uint8_t expected[] = {0x2a, 0x2b, 0x90, 0x90};

    AutoAssembler failing;
    failing.registerCommand("failcmd", [](const std::string&, std::vector<std::string>&,
        std::vector<std::string>&, std::string& error) {
        error = "failcmd parse error";
        return false;
    });
    auto failedCheck = failing.check("[ENABLE]\nfailcmd()\n");

    bool ok = result.success &&
        std::memcmp(actual, expected, sizeof(actual)) == 0 &&
        !failedCheck.success &&
        failedCheck.error == "failcmd parse error";

    proc.free(addr, 4096);
    printf("  custom commands: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_processing_hooks(pid_t pid) {
    printf("\n── Test: AutoAssembler processing hooks ──\n");

    LinuxProcessHandle proc(pid);
    auto allocResult = proc.allocate(4096, MemProt::All);
    if (!allocResult) {
        printf("  processing hooks: FAILED\n");
        return;
    }
    uintptr_t addr = *allocResult;

    AutoAssembler aa;
    aa.addPreprocessorHook([](std::string& code, std::vector<std::string>& log, std::string&) {
        code += "\nnop 1\n";
        log.push_back("pre-hook");
        return true;
    });
    aa.addPostprocessorHook([](std::string& code, std::vector<std::string>& log, std::string&) {
        code += "\ndb 2A\n";
        log.push_back("post-hook");
        return true;
    });

    char script[128];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "%lx:\n",
        addr);

    auto result = aa.execute(proc, script);
    uint8_t actual[2] = {};
    proc.read(addr, actual, sizeof(actual));
    const uint8_t expected[] = {0x90, 0x2a};

    auto checkResult = aa.check(script);

    AutoAssembler failing;
    failing.addPostprocessorHook([](std::string&, std::vector<std::string>&, std::string& error) {
        error = "post hook parse stop";
        return false;
    });
    auto failedCheck = failing.check("[ENABLE]\nnop 1\n");

    bool ok = result.success &&
        std::memcmp(actual, expected, sizeof(actual)) == 0 &&
        checkResult.success &&
        !failedCheck.success &&
        failedCheck.error == "post hook parse stop";

    proc.free(addr, 4096);
    printf("  processing hooks: %s\n", ok ? "OK" : "FAILED");
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

static void test_autoassembler_loadlibrary(pid_t pid) {
    printf("\n── Test: AutoAssembler loadlibrary ──\n");

    auto exePath = std::filesystem::read_symlink("/proc/self/exe");
    auto libraryPath = exePath.parent_path() / "libspeedhack.so";
    if (!std::filesystem::exists(libraryPath)) {
        printf("  loadlibrary: SKIPPED (libspeedhack.so not found)\n");
        return;
    }

    char script[1024];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "loadlibrary(\"%s\")\n",
        libraryPath.c_str());

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;
    auto result = aa.execute(proc, script);

    bool sawLog = false;
    for (const auto& line : result.log) {
        if (line.find("LOADLIBRARY: ") == 0) {
            sawLog = true;
            break;
        }
    }

    bool ok = result.success && sawLog;
    printf("  loadlibrary: %s\n", ok ? "OK" : "FAILED");
    if (!ok && !result.error.empty())
        printf("    error: %s\n", result.error.c_str());
}

static void test_autoassembler_struct_definitions(pid_t pid) {
    printf("\n── Test: AutoAssembler struct definitions ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;
    auto result = aa.execute(proc,
        "[ENABLE]\n"
        "struct stackview\n"
        "returnaddress:\n"
        "  dd ?\n"
        "param1:\n"
        "  dq ?\n"
        "param2:\n"
        "  dd ?\n"
        "endstruct\n"
        "alloc(structblock, 4096)\n"
        "structblock:\n"
        "mov eax, stackview.returnaddress\n"
        "mov ebx, param1\n"
        "mov ecx, stackview\n");

    uint8_t actual[15] = {};
    if (result.success && !result.disableInfo.allocs.empty())
        proc.read(result.disableInfo.allocs[0].address, actual, sizeof(actual));

    const uint8_t expected[] = {
        0xb8, 0x00, 0x00, 0x00, 0x00,
        0xbb, 0x04, 0x00, 0x00, 0x00,
        0xb9, 0x10, 0x00, 0x00, 0x00
    };

    bool ok = result.success && std::memcmp(actual, expected, sizeof(expected)) == 0;
    if (result.success)
        aa.disable(proc, "", result.disableInfo);

    printf("  struct definitions: %s\n", ok ? "OK" : "FAILED");
    if (!ok && !result.error.empty())
        printf("    error: %s\n", result.error.c_str());
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

static void test_lua_utility_bindings() {
    printf("\n── Test: Lua utility bindings ──\n");

    LuaEngine lua;
    auto err = lua.execute(
        "showMessage('utility smoke test')\n"
        "assert(messageDialog('utility dialog', mtInformation, mbOK) == mrOK)\n"
        "local canvas = getScreenCanvas()\n"
        "assert(type(canvas) == 'table')\n"
        "assert(canvas.Width > 0 and canvas.Height > 0)\n"
        "assert(canvas.Pen.Color == 0xffffff)\n"
        "assert(canvas.Brush.Color == 0x000000)\n"
        "assert(canvas:TextOut(10, 20, 'hello'))\n"
        "assert(canvas:Line(0, 0, 10, 10))\n"
        "assert(canvas:getTextWidth('abcd') == 32)\n"
        "assert(canvas:getTextHeight('abcd') == 16)\n"
        "assert(canvas:getPixel(1, 1) == 0)\n"
        "assert(#canvas.commands == 2)\n");

    printf("  showMessage/messageDialog/getScreenCanvas: %s\n", err.empty() ? "OK" : "FAILED");
}

static void test_lua_hotkey_bindings() {
    printf("\n── Test: Lua hotkey bindings ──\n");

    LuaEngine lua;
    auto err = lua.execute(
        "local hits = 0\n"
        "local hk = createHotkey(function() hits = hits + 1 end, VK_F1, VK_F2)\n"
        "local keys = hk:getKeys()\n"
        "assert(keys[1] == VK_F1 and keys[2] == VK_F2)\n"
        "assert(hk:trigger() == true and hits == 1)\n"
        "setHotkeyAction(hk, function() hits = hits + 10 end)\n"
        "assert(hk:doHotkey() == true and hits == 11)\n"
        "hk.Enabled = false\n"
        "assert(hk:trigger() == false and hits == 11)\n"
        "hk.Enabled = true\n"
        "assert(hk:trigger() == true and hits == 21)\n"
        "hk:destroy()\n"
        "assert(hk:trigger() == false and hits == 21)\n");

    printf("  createHotkey/setHotkeyAction: %s\n", err.empty() ? "OK" : "FAILED");
}

static void test_lua_thread_bindings() {
    printf("\n── Test: Lua thread bindings ──\n");

    LuaEngine lua;
    auto err = lua.execute(
        "local hits = 0\n"
        "local t = createThread(function() hits = hits + 1 end)\n"
        "assert(type(t) == 'userdata')\n"
        "assert(t.Finished == true and t:waitfor() == true)\n"
        "t.Name = 'worker'\n"
        "assert(t.Name == 'worker')\n"
        "local s = createThread(function() hits = hits + 10 end, true)\n"
        "assert(s.Suspended == true and s.Finished == false)\n"
        "assert(s:resume() == true)\n"
        "assert(s.Finished == true)\n"
        "local value = synchronize(function() return 7 end)\n"
        "assert(value == 7)\n"
        "assert(queue(function() hits = hits + 100 end) == true)\n"
        "assert(hits == 111)\n"
        "local dead = createThread(function() hits = hits + 1000 end, true)\n"
        "assert(dead:terminate() == true and dead.Terminated == true)\n"
        "assert(dead:resume() == true and hits == 111)\n");

    printf("  createThread/synchronize/queue: %s\n", err.empty() ? "OK" : "FAILED");
    if (!err.empty())
        printf("    error: %s\n", err.c_str());
}

static void test_lua_custom_type_bindings() {
    printf("\n── Test: Lua custom type bindings ──\n");

    LuaEngine lua;
    auto err = lua.execute(
        "assert(registerCustomTypeLua('u16x10', 2,\n"
        "  function(bytes)\n"
        "    local lo, hi = string.byte(bytes, 1, 2)\n"
        "    return (lo + hi * 256) * 10\n"
        "  end,\n"
        "  function(value)\n"
        "    local raw = math.floor(value / 10)\n"
        "    return string.char(raw % 256, math.floor(raw / 256) % 256)\n"
        "  end))\n"
        "assert(getCustomTypeSize('u16x10') == 2)\n"
        "assert(getCustomType('u16x10').Name == 'u16x10')\n"
        "assert(customTypeToValue('u16x10', string.char(0x34, 0x12)) == 0x1234 * 10)\n"
        "assert(customTypeToValue('u16x10', {0x34, 0x12}) == 0x1234 * 10)\n"
        "local bytes = customTypeToBytes('u16x10', 0x1234 * 10)\n"
        "assert(bytes[1] == 0x34 and bytes[2] == 0x12)\n"
        "assert(unregisterCustomType('u16x10'))\n"
        "assert(getCustomType('u16x10') == nil)\n");

    printf("  registerCustomTypeLua/customTypeToValue: %s\n", err.empty() ? "OK" : "FAILED");
    if (!err.empty())
        printf("    error: %s\n", err.c_str());
}

static void test_lua_address_list_bindings() {
    printf("\n── Test: Lua address list bindings ──\n");

    LuaEngine lua;
    auto err = lua.execute(
        "addressList_clear()\n"
        "assert(addressList_getCount() == 0)\n"
        "local first = addressList_addEntry({Description='Health', Address='0x1000', Type='i32', Value='100', Active=false})\n"
        "assert(first == 0)\n"
        "assert(addressList_getCount() == 1)\n"
        "local entry = getTableEntry(0)\n"
        "assert(entry.Description == 'Health' and entry.Address == '0x1000')\n"
        "assert(setTableEntry(0, {Description='Mana', Address='0x2000', Type='float', Value='12.5', Active=true}))\n"
        "entry = getTableEntry(0)\n"
        "assert(entry.Description == 'Mana' and entry.Active == true)\n"
        "addressList_addEntry({Description='Ammo', Address='0x3000'})\n"
        "assert(addressList_getCount() == 2)\n"
        "assert(addressList_removeEntry(0) == true)\n"
        "assert(addressList_getCount() == 1)\n"
        "assert(getTableEntry(0).Description == 'Ammo')\n"
        "assert(addressList_removeEntry(99) == false)\n"
        "addressList_clear()\n"
        "assert(addressList_getCount() == 0)\n");

    printf("  getTableEntry/setTableEntry/addressList: %s\n", err.empty() ? "OK" : "FAILED");
}

static void test_lua_debug_bindings() {
    printf("\n── Test: Lua debug bindings ──\n");

    LuaEngine lua;
    auto err = lua.execute(
        "assert(debug_isDebugging() == false)\n"
        "assert(debug_isBroken() == false)\n"
        "local id = debug_setBreakpoint(0x401000, bptExecute, 1)\n"
        "assert(type(id) == 'number' and id > 0)\n"
        "assert(debug_isDebugging() == true)\n"
        "local list = debug_getBreakpointList()\n"
        "assert(#list == 1)\n"
        "assert(list[1].id == id and list[1].address == 0x401000)\n"
        "assert(list[1].type == bptExecute and list[1].size == 1)\n"
        "assert(debug_continueFromBreakpoint() == true)\n"
        "assert(debug_removeBreakpoint(id) == true)\n"
        "assert(#debug_getBreakpointList() == 0)\n"
        "assert(debug_isDebugging() == false)\n");

    printf("  debug_set/remove/list/state: %s\n", err.empty() ? "OK" : "FAILED");
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

static void test_codepage_string_scan() {
    printf("\n── Test: Codepage string scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  ISO-8859-1 match: FAILED\n");
        return;
    }

    auto base = reinterpret_cast<uintptr_t>(page);
    auto* bytes = reinterpret_cast<uint8_t*>(page);
    std::memset(bytes, 0, pageSize);
    bytes[32] = 0xe9; // U+00E9 encoded as ISO-8859-1.

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    ScanConfig config;
    config.valueType = ValueType::String;
    config.compareType = ScanCompare::Exact;
    config.stringValue = "\xc3\xa9"; // U+00E9 in UTF-8 source text.
    config.stringEncoding = "ISO-8859-1";
    config.alignment = 1;
    config.startAddress = base;
    config.stopAddress = base + pageSize;

    auto result = scanner.firstScan(proc, config);
    bool ok = result.count() == 1 && result.address(0) == base + 32;

    ScanConfig next = config;
    auto nextResult = scanner.nextScan(proc, next, result);
    ok = ok && nextResult.count() == 1 && nextResult.address(0) == base + 32;

    munmap(page, pageSize);

    printf("  ISO-8859-1 match: %s\n", ok ? "OK" : "FAILED");
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

static void test_grouped_scan() {
    printf("\n── Test: Grouped scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  grouped first/next: FAILED\n");
        return;
    }

    std::memset(page, 0x7f, pageSize);
    auto base = reinterpret_cast<uintptr_t>(page);
    auto* bytes = reinterpret_cast<uint8_t*>(page);

    int32_t i32Value = 1337;
    float floatValue = 2.5f;
    uint8_t byteValue = 66;
    std::memcpy(bytes + 128, &i32Value, sizeof(i32Value));
    std::memcpy(bytes + 132, &floatValue, sizeof(floatValue));
    std::memcpy(bytes + 136, &byteValue, sizeof(byteValue));

    uint8_t nearMiss = 65;
    std::memcpy(bytes + 256, &i32Value, sizeof(i32Value));
    std::memcpy(bytes + 260, &floatValue, sizeof(floatValue));
    std::memcpy(bytes + 264, &nearMiss, sizeof(nearMiss));

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    ScanConfig grouped;
    grouped.valueType = ValueType::Grouped;
    grouped.compareType = ScanCompare::Exact;
    grouped.alignment = 1;
    grouped.startAddress = base;
    grouped.stopAddress = base + pageSize;
    std::string groupedError;
    bool parsed = grouped.parseGrouped("i32:1337@0;float:2.5@4;byte:66@8", &groupedError);

    bool ok = parsed;
    auto first = parsed ? scanner.firstScan(proc, grouped) : ScanResult{};
    ok = ok && first.count() == 1 && first.address(0) == base + 128;

    byteValue = 67;
    std::memcpy(bytes + 136, &byteValue, sizeof(byteValue));

    ScanConfig changed = grouped;
    changed.compareType = ScanCompare::Changed;
    auto changedResult = parsed ? scanner.nextScan(proc, changed, first) : ScanResult{};
    ok = ok && changedResult.count() == 1 && changedResult.address(0) == base + 128;

    uint8_t firstBlock[9] = {};
    if (changedResult.count() > 0)
        changedResult.firstValue(0, firstBlock, sizeof(firstBlock));
    ok = ok && firstBlock[8] == 66;

    ScanConfig groupedUpdated = grouped;
    groupedUpdated.compareType = ScanCompare::Exact;
    parsed = groupedUpdated.parseGrouped("i32:1337@0;float:2.5@4;byte:67@8", &groupedError);
    ok = ok && parsed;
    auto exactResult = parsed ? scanner.nextScan(proc, groupedUpdated, changedResult) : ScanResult{};
    ok = ok && exactResult.count() == 1 && exactResult.address(0) == base + 128;

    munmap(page, pageSize);

    printf("  grouped first/next: %s\n", ok ? "OK" : "FAILED");
}

static void test_custom_formula_scan() {
    printf("\n── Test: Custom formula scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  custom Lua formula: FAILED\n");
        return;
    }

    std::memset(page, 0x55, pageSize);
    auto base = reinterpret_cast<uintptr_t>(page);
    auto* bytes = reinterpret_cast<uint8_t*>(page);

    uint32_t target = 0x1234ABCD;
    uint32_t decoy = 0x1234ABCE;
    std::memcpy(bytes + 64, &target, sizeof(target));
    std::memcpy(bytes + 128, &decoy, sizeof(decoy));

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    ScanConfig custom;
    custom.valueType = ValueType::Custom;
    custom.compareType = ScanCompare::Exact;
    custom.customValueSize = 4;
    custom.customFormula =
        "local b1,b2,b3,b4 = string.byte(current,1,4)\n"
        "return b1 == 0xCD and b2 == 0xAB and b3 == 0x34 and b4 == 0x12";
    custom.alignment = 4;
    custom.startAddress = base;
    custom.stopAddress = base + pageSize;

    auto first = scanner.firstScan(proc, custom);
    bool ok = first.count() == 1 && first.address(0) == base + 64;

    uint32_t changedValue = 0x1234ABCF;
    std::memcpy(bytes + 64, &changedValue, sizeof(changedValue));

    ScanConfig changed = custom;
    changed.compareType = ScanCompare::Changed;
    auto changedResult = scanner.nextScan(proc, changed, first);
    ok = ok && changedResult.count() == 1 && changedResult.address(0) == base + 64;

    std::memcpy(bytes + 64, &target, sizeof(target));
    auto exactResult = scanner.nextScan(proc, custom, changedResult);
    ok = ok && exactResult.count() == 1 && exactResult.address(0) == base + 64;

    munmap(page, pageSize);

    printf("  custom Lua formula: %s\n", ok ? "OK" : "FAILED");
}

static void test_lua_memscan_grouped_custom() {
    printf("\n── Test: Lua memscan grouped/custom ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  soCustom/vtGrouped: FAILED\n");
        return;
    }

    std::memset(page, 0x22, pageSize);
    auto base = reinterpret_cast<uintptr_t>(page);
    auto* bytes = reinterpret_cast<uint8_t*>(page);
    int32_t dwordValue = 777;
    float floatValue = 1.5f;
    std::memcpy(bytes, &dwordValue, sizeof(dwordValue));
    std::memcpy(bytes + 4, &floatValue, sizeof(floatValue));

    LinuxProcessHandle proc(getpid());
    LuaEngine lua;
    lua.setProcess(&proc);

    std::string script =
        "local base = " + std::to_string(base) + "\n"
        "local stop = base + " + std::to_string(pageSize) + "\n"
        "local grouped = createMemScan()\n"
        "assert(grouped:firstScan(soExactValue, vtGrouped, 'i32:777@0;float:1.5@4', base, stop, 1))\n"
        "assert(grouped:getFoundCount() == 1)\n"
        "assert(grouped:getAddress(0) == base)\n"
        "local custom = createMemScan()\n"
        "assert(custom:firstScan(soCustom, vtDword, 'local b1,b2,b3,b4=string.byte(current,1,4); return b1==0x09 and b2==0x03 and b3==0 and b4==0', base, stop, 4))\n"
        "assert(custom:getFoundCount() == 1)\n"
        "assert(custom:getAddress(0) == base)\n";

    auto err = lua.execute(script);
    munmap(page, pageSize);

    printf("  soCustom/vtGrouped: %s\n", err.empty() ? "OK" : "FAILED");
}

static void test_percentage_scan() {
    printf("\n── Test: Percentage scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  increased/between by percent: FAILED\n");
        return;
    }

    auto base = reinterpret_cast<uintptr_t>(page);
    auto* value = reinterpret_cast<int32_t*>(page);
    *value = 100;

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    ScanConfig first;
    first.valueType = ValueType::Int32;
    first.compareType = ScanCompare::Exact;
    first.intValue = 100;
    first.alignment = 4;
    first.startAddress = base;
    first.stopAddress = base + pageSize;

    auto initial = scanner.firstScan(proc, first);
    *value = 125;

    ScanConfig increased = first;
    increased.compareType = ScanCompare::Increased;
    increased.percentageScan = true;
    increased.percentageValue = 20.0;
    auto increasedResult = scanner.nextScan(proc, increased, initial);

    ScanConfig between = increased;
    between.compareType = ScanCompare::Between;
    between.percentageValue = 20.0;
    between.percentageValue2 = 30.0;
    auto betweenResult = scanner.nextScan(proc, between, initial);

    ScanConfig tooHigh = increased;
    tooHigh.percentageValue = 30.0;
    auto tooHighResult = scanner.nextScan(proc, tooHigh, initial);

    bool ok = initial.count() == 1 &&
        increasedResult.count() == 1 && increasedResult.address(0) == base &&
        betweenResult.count() == 1 && betweenResult.address(0) == base &&
        tooHighResult.count() == 0;

    munmap(page, pageSize);

    printf("  increased/between by percent: %s\n", ok ? "OK" : "FAILED");
}

static void test_same_as_first_scan() {
    printf("\n── Test: Same-as-first scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  same as first: FAILED\n");
        return;
    }

    auto base = reinterpret_cast<uintptr_t>(page);
    auto* value = reinterpret_cast<int32_t*>(page);
    *value = 100;

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    ScanConfig first;
    first.valueType = ValueType::Int32;
    first.compareType = ScanCompare::Exact;
    first.intValue = 100;
    first.alignment = 4;
    first.startAddress = base;
    first.stopAddress = base + pageSize;

    auto initial = scanner.firstScan(proc, first);

    *value = 200;
    ScanConfig changed = first;
    changed.compareType = ScanCompare::Changed;
    auto changedResult = scanner.nextScan(proc, changed, initial);

    *value = 100;
    ScanConfig same = first;
    same.compareType = ScanCompare::SameAsFirst;
    auto sameResult = scanner.nextScan(proc, same, changedResult);

    *value = 200;
    auto differentResult = scanner.nextScan(proc, same, changedResult);

    int32_t firstValue = 0;
    if (changedResult.count() > 0)
        changedResult.firstValue(0, &firstValue, sizeof(firstValue));

    bool ok = initial.count() == 1 &&
        changedResult.count() == 1 && changedResult.address(0) == base &&
        firstValue == 100 &&
        sameResult.count() == 1 && sameResult.address(0) == base &&
        differentResult.count() == 0;

    munmap(page, pageSize);

    printf("  same as first: %s\n", ok ? "OK" : "FAILED");
}

static void test_pointer_type_scan() {
    printf("\n── Test: Pointer type scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  pointer scan: FAILED\n");
        return;
    }

    auto base = reinterpret_cast<uintptr_t>(page);
    auto* pointerSlot = reinterpret_cast<uintptr_t*>(page);
    *pointerSlot = base + 128;

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    ScanConfig config;
    config.valueType = ValueType::Pointer;
    config.compareType = ScanCompare::Exact;
    config.intValue = static_cast<int64_t>(base + 128);
    config.alignment = sizeof(uintptr_t);
    config.startAddress = base;
    config.stopAddress = base + pageSize;

    auto first = scanner.firstScan(proc, config);

    *pointerSlot = base + 256;
    config.intValue = static_cast<int64_t>(base + 256);
    auto next = scanner.nextScan(proc, config, first);

    uintptr_t stored = 0;
    if (next.count() > 0)
        next.value(0, &stored, sizeof(stored));

    bool ok = first.count() == 1 && first.address(0) == base &&
        next.count() == 1 && next.address(0) == base &&
        stored == base + 256;

    munmap(page, pageSize);

    printf("  pointer scan: %s\n", ok ? "OK" : "FAILED");
}

static void test_float_rounding_scan() {
    printf("\n── Test: Float rounding scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  rounded/truncated/extreme: FAILED\n");
        return;
    }

    std::memset(page, 0x7f, pageSize);
    auto base = reinterpret_cast<uintptr_t>(page);
    auto* bytes = reinterpret_cast<uint8_t*>(page);
    float roundedA = 42.4f;
    float roundedB = 42.01f;
    float notRounded = 42.6f;
    std::memcpy(bytes + 16, &roundedA, sizeof(roundedA));
    std::memcpy(bytes + 32, &notRounded, sizeof(notRounded));
    std::memcpy(bytes + 48, &roundedB, sizeof(roundedB));

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    ScanConfig config;
    config.valueType = ValueType::Float;
    config.compareType = ScanCompare::Exact;
    config.floatValue = 42.0;
    config.alignment = 4;
    config.startAddress = base;
    config.stopAddress = base + pageSize;

    config.roundingType = 1;
    auto roundedResult = scanner.firstScan(proc, config);

    config.roundingType = 2;
    auto truncatedResult = scanner.firstScan(proc, config);

    config.roundingType = 3;
    config.floatTolerance = 0.02;
    auto extremeResult = scanner.firstScan(proc, config);

    auto hasAddress = [](const ScanResult& result, uintptr_t address) {
        for (size_t i = 0; i < result.count(); ++i)
            if (result.address(i) == address)
                return true;
        return false;
    };

    bool roundedOk = roundedResult.count() == 2 &&
        hasAddress(roundedResult, base + 16) &&
        hasAddress(roundedResult, base + 48);
    bool truncatedOk = truncatedResult.count() == 3 &&
        hasAddress(truncatedResult, base + 16) &&
        hasAddress(truncatedResult, base + 32) &&
        hasAddress(truncatedResult, base + 48);
    bool extremeOk = extremeResult.count() == 1 &&
        extremeResult.address(0) == base + 48;

    munmap(page, pageSize);

    printf("  rounded/truncated/extreme: %s\n",
        (roundedOk && truncatedOk && extremeOk) ? "OK" : "FAILED");
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
    test_trainer_generation();
    test_code_analysis_references();
    test_managed_runtime_detection();
    test_managed_object_enumeration();
    test_managed_type_extraction();
    test_gdb_remote_client();
    test_ceserver_client();
    test_network_compression();
    test_distributed_pointer_scan();
    test_stack_trace_frame_walk();
    test_break_and_trace();
    test_exception_breakpoint();
    test_structure_tools();
    test_autoassembler_unregister_symbol(targetPid);
    test_autoassembler_dealloc(targetPid);
    test_autoassembler_data_directive_widths(targetPid);
    test_autoassembler_nop_fillmem(targetPid);
    test_autoassembler_forward_labels(targetPid);
    test_autoassembler_create_thread(targetPid);
    test_autoassembler_ds(targetPid);
    test_autoassembler_custom_commands(targetPid);
    test_autoassembler_processing_hooks(targetPid);
    test_autoassembler_loadbinary(targetPid);
    test_autoassembler_loadlibrary(targetPid);
    test_autoassembler_struct_definitions(targetPid);
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
    test_lua_utility_bindings();
    test_lua_hotkey_bindings();
    test_lua_thread_bindings();
    test_lua_custom_type_bindings();
    test_lua_address_list_bindings();
    test_lua_debug_bindings();
    test_lua_process_bindings(targetPid);
    test_lua_memscan();
    test_binary_scan_bitmask();
    test_unicode_string_scan();
    test_codepage_string_scan();
    test_all_types_scan();
    test_grouped_scan();
    test_custom_formula_scan();
    test_percentage_scan();
    test_same_as_first_scan();
    test_pointer_type_scan();
    test_float_rounding_scan();
    test_lua_memscan_grouped_custom();
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
