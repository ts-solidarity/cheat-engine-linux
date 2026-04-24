/// cescan — Cheat Engine CLI for Linux
/// Usage: sudo cescan <command> [args...]

#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "scanner/memory_scanner.hpp"
#include "arch/disassembler.hpp"
#include "arch/assembler.hpp"
#include "core/autoasm.hpp"
#include "symbols/elf_symbols.hpp"
#include "scanner/pointer_scanner.hpp"
#include <fstream>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <algorithm>
#include <getopt.h>
#include <unistd.h>

using namespace ce;
using namespace ce::os;

// ── Helpers ──

static void usage() {
    fprintf(stderr,
        "cescan — Cheat Engine CLI for Linux\n"
        "\n"
        "Usage: sudo cescan <command> [args...]\n"
        "\n"
        "Commands:\n"
        "  list                          List all processes\n"
        "  scan <pid> [options]          Scan process memory\n"
        "  read <pid> <addr> [size]      Read memory (default 64 bytes)\n"
        "  write <pid> <addr> <val>      Write value to address\n"
        "  disasm <pid> <addr> [count]   Disassemble instructions\n"
        "  modules <pid>                 List loaded modules\n"
        "  regions <pid>                 List memory regions\n"
        "\n"
        "Scan options:\n"
        "  --type <type>     byte, i16, i32, i64, float, double, string, aob, binary (default: i32)\n"
        "  --value <val>     Value to search for\n"
        "  --value2 <val>    Second value (for 'between')\n"
        "  --compare <cmp>   exact, greater, less, between, changed,\n"
        "                    unchanged, increased, decreased, unknown\n"
        "  --previous <dir>  Previous scan result directory (for next scan)\n"
        "  --align <n>       Scan alignment (default: 4)\n"
        "  --writable        Only scan writable memory\n"
        "\n"
        "Write options:\n"
        "  --type <type>     byte, i16, i32, i64, float, double (default: i32)\n"
    );
}

static ValueType parseType(const char* s) {
    if (!strcmp(s, "byte"))   return ValueType::Byte;
    if (!strcmp(s, "i16"))    return ValueType::Int16;
    if (!strcmp(s, "i32"))    return ValueType::Int32;
    if (!strcmp(s, "i64"))    return ValueType::Int64;
    if (!strcmp(s, "float"))  return ValueType::Float;
    if (!strcmp(s, "double")) return ValueType::Double;
    if (!strcmp(s, "string")) return ValueType::String;
    if (!strcmp(s, "aob"))    return ValueType::ByteArray;
    if (!strcmp(s, "binary")) return ValueType::Binary;
    fprintf(stderr, "Unknown type: %s\n", s);
    exit(1);
}

static ScanCompare parseCompare(const char* s) {
    if (!strcmp(s, "exact"))     return ScanCompare::Exact;
    if (!strcmp(s, "greater"))   return ScanCompare::Greater;
    if (!strcmp(s, "less"))      return ScanCompare::Less;
    if (!strcmp(s, "between"))   return ScanCompare::Between;
    if (!strcmp(s, "changed"))   return ScanCompare::Changed;
    if (!strcmp(s, "unchanged")) return ScanCompare::Unchanged;
    if (!strcmp(s, "increased")) return ScanCompare::Increased;
    if (!strcmp(s, "decreased")) return ScanCompare::Decreased;
    if (!strcmp(s, "unknown"))   return ScanCompare::Unknown;
    fprintf(stderr, "Unknown compare: %s\n", s);
    exit(1);
}

static size_t typeSize(ValueType vt) {
    switch (vt) {
        case ValueType::Byte:   return 1;
        case ValueType::Int16:  return 2;
        case ValueType::Int32:  return 4;
        case ValueType::Int64:  return 8;
        case ValueType::Float:  return 4;
        case ValueType::Double: return 8;
        default: return 4;
    }
}

// ── Commands ──

static int cmd_list() {
    LinuxProcessEnumerator enumerator;
    auto procs = enumerator.list();
    printf("%-8s  %s\n", "PID", "NAME");
    for (auto& p : procs)
        printf("%-8d  %s\n", p.pid, p.name.c_str());
    printf("\n%zu processes\n", procs.size());
    return 0;
}

static int cmd_regions(pid_t pid) {
    LinuxProcessHandle proc(pid);
    auto regions = proc.queryRegions();
    printf("%-18s  %-18s  %10s  %-4s  %s\n", "START", "END", "SIZE", "PERM", "PATH");
    size_t totalReadable = 0;
    for (auto& r : regions) {
        char perms[4] = "---";
        if (r.protection & MemProt::Read)  perms[0] = 'r';
        if (r.protection & MemProt::Write) perms[1] = 'w';
        if (r.protection & MemProt::Exec)  perms[2] = 'x';
        printf("%018lx  %018lx  %10zu  %s   %s\n",
            r.base, r.base + r.size, r.size, perms, r.path.c_str());
        if (r.protection & MemProt::Read) totalReadable += r.size;
    }
    printf("\n%zu regions, %zu bytes (%.1f MB) readable\n",
        regions.size(), totalReadable, totalReadable / 1048576.0);
    return 0;
}

static int cmd_modules(pid_t pid) {
    LinuxProcessHandle proc(pid);
    auto mods = proc.modules();
    printf("%-18s  %10s  %s\n", "BASE", "SIZE", "NAME");
    for (auto& m : mods)
        printf("%018lx  %10zu  %s\n", m.base, m.size, m.name.c_str());
    printf("\n%zu modules\n", mods.size());
    return 0;
}

static int cmd_read(pid_t pid, uintptr_t addr, size_t size) {
    LinuxProcessHandle proc(pid);
    std::vector<uint8_t> buf(size);
    auto r = proc.read(addr, buf.data(), size);
    if (!r) {
        fprintf(stderr, "Read failed: %s\n", r.error().message().c_str());
        return 1;
    }
    size_t n = *r;
    for (size_t i = 0; i < n; i += 16) {
        printf("%018lx  ", addr + i);
        for (size_t j = 0; j < 16 && i + j < n; ++j)
            printf("%02x ", buf[i + j]);
        for (size_t j = n - i; j < 16; ++j)
            printf("   ");
        printf(" ");
        for (size_t j = 0; j < 16 && i + j < n; ++j) {
            uint8_t c = buf[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        printf("\n");
    }
    return 0;
}

static int cmd_write(pid_t pid, uintptr_t addr, const char* valStr, ValueType vt) {
    LinuxProcessHandle proc(pid);
    uint8_t buf[8] = {};
    size_t sz = typeSize(vt);

    switch (vt) {
        case ValueType::Byte:   { uint8_t v = atoi(valStr); memcpy(buf, &v, 1); break; }
        case ValueType::Int16:  { int16_t v = atoi(valStr); memcpy(buf, &v, 2); break; }
        case ValueType::Int32:  { int32_t v = atoi(valStr); memcpy(buf, &v, 4); break; }
        case ValueType::Int64:  { int64_t v = atoll(valStr); memcpy(buf, &v, 8); break; }
        case ValueType::Float:  { float v = atof(valStr); memcpy(buf, &v, 4); break; }
        case ValueType::Double: { double v = atof(valStr); memcpy(buf, &v, 8); break; }
        default: break;
    }

    auto r = proc.write(addr, buf, sz);
    if (!r) {
        fprintf(stderr, "Write failed: %s\n", r.error().message().c_str());
        return 1;
    }
    printf("Wrote %zu bytes to 0x%lx\n", sz, addr);
    return 0;
}

static int cmd_disasm(pid_t pid, uintptr_t addr, size_t count) {
    LinuxProcessHandle proc(pid);

    // Load symbols for annotation
    SymbolResolver resolver;
    resolver.loadProcess(proc);

    std::vector<uint8_t> buf(count * 15);
    auto r = proc.read(addr, buf.data(), buf.size());
    if (!r) {
        fprintf(stderr, "Read failed: %s\n", r.error().message().c_str());
        return 1;
    }

    Disassembler dis(Arch::X86_64);
    auto insns = dis.disassemble(addr, {buf.data(), *r}, count);
    for (auto& i : insns) {
        // Resolve the instruction address itself
        auto addrSym = resolver.resolve(i.address);
        if (!addrSym.empty())
            printf("  ; %s\n", addrSym.c_str());
        printf("%s\n", i.toString().c_str());
    }
    printf("\n%zu instructions\n", insns.size());
    return 0;
}

static int cmd_scan(pid_t pid, int argc, char** argv) {
    ScanConfig config;
    config.valueType = ValueType::Int32;
    config.compareType = ScanCompare::Exact;
    config.alignment = 4;
    const char* previousDir = nullptr;
    const char* valueStr = nullptr;
    const char* value2Str = nullptr;

    static struct option long_opts[] = {
        {"type",     required_argument, nullptr, 't'},
        {"value",    required_argument, nullptr, 'v'},
        {"value2",   required_argument, nullptr, '2'},
        {"compare",  required_argument, nullptr, 'c'},
        {"previous", required_argument, nullptr, 'p'},
        {"align",    required_argument, nullptr, 'a'},
        {"writable", no_argument,       nullptr, 'w'},
        {nullptr, 0, nullptr, 0}
    };

    optind = 1; // reset getopt
    int opt;
    while ((opt = getopt_long(argc, argv, "t:v:2:c:p:a:w", long_opts, nullptr)) != -1) {
        switch (opt) {
            case 't': config.valueType = parseType(optarg); break;
            case 'v': valueStr = optarg; break;
            case '2': value2Str = optarg; break;
            case 'c': config.compareType = parseCompare(optarg); break;
            case 'p': previousDir = optarg; break;
            case 'a': config.alignment = atoi(optarg); break;
            case 'w': config.scanWritableOnly = true; break;
        }
    }

    if (valueStr) {
        if (config.valueType == ValueType::String) {
            config.stringValue = valueStr;
            config.alignment = 1;
        } else if (config.valueType == ValueType::ByteArray) {
            config.parseAOB(valueStr);
            config.alignment = 1;
        } else if (config.valueType == ValueType::Binary) {
            config.parseBinary(valueStr);
            config.alignment = 1;
        } else if (config.valueType == ValueType::Float || config.valueType == ValueType::Double) {
            config.floatValue = atof(valueStr);
            if (value2Str) config.floatValue2 = atof(value2Str);
        } else {
            config.intValue = atoll(valueStr);
            if (value2Str) config.intValue2 = atoll(value2Str);
        }
    }

    LinuxProcessHandle proc(pid);
    MemoryScanner scanner;

    if (previousDir) {
        // Next scan
        ScanResult previous{std::filesystem::path(previousDir)};
        printf("Next scan on %zu previous results...\n", previous.count());
        auto result = scanner.nextScan(proc, config, previous);
        printf("Found: %zu results\n", result.count());
        printf("Results: %s\n", result.directory().c_str());

        size_t vs = typeSize(config.valueType);
        size_t show = std::min(result.count(), size_t(20));
        for (size_t i = 0; i < show; ++i) {
            uintptr_t addr = result.address(i);
            uint8_t val[8];
            result.value(i, val, vs);
            printf("  0x%lx = ", addr);
            switch (config.valueType) {
                case ValueType::Int32: { int32_t v; memcpy(&v, val, 4); printf("%d", v); break; }
                case ValueType::Float: { float v; memcpy(&v, val, 4); printf("%f", v); break; }
                default: {
                    for (size_t j = 0; j < vs; ++j) printf("%02x", val[j]);
                }
            }
            printf("\n");
        }
        if (result.count() > 20) printf("  ... and %zu more\n", result.count() - 20);
    } else {
        // First scan
        printf("Scanning PID %d...\n", pid);
        auto result = scanner.firstScan(proc, config);
        printf("Found: %zu results\n", result.count());
        printf("Results: %s\n", result.directory().c_str());

        size_t vs = typeSize(config.valueType);
        size_t show = std::min(result.count(), size_t(20));
        for (size_t i = 0; i < show; ++i) {
            uintptr_t addr = result.address(i);
            uint8_t val[8];
            result.value(i, val, vs);
            printf("  0x%lx = ", addr);
            switch (config.valueType) {
                case ValueType::Int32: { int32_t v; memcpy(&v, val, 4); printf("%d", v); break; }
                case ValueType::Float: { float v; memcpy(&v, val, 4); printf("%f", v); break; }
                default: {
                    for (size_t j = 0; j < vs; ++j) printf("%02x", val[j]);
                }
            }
            printf("\n");
        }
        if (result.count() > 20) printf("  ... and %zu more\n", result.count() - 20);
    }
    return 0;
}

static int cmd_symbols(pid_t pid) {
    LinuxProcessHandle proc(pid);
    SymbolResolver resolver;
    resolver.loadProcess(proc);
    printf("%-18s  %-8s  %-30s  %s\n", "ADDRESS", "SIZE", "NAME", "MODULE");
    int shown = 0;
    for (auto& s : resolver.symbols()) {
        if (s.address == 0) continue;
        printf("%018lx  %8zu  %-30s  %s\n", s.address, s.size, s.name.c_str(), s.module.c_str());
        if (++shown >= 200) { printf("... and %zu more\n", resolver.count() - 200); break; }
    }
    printf("\n%zu symbols loaded\n", resolver.count());
    return 0;
}

static int cmd_pointerscan(pid_t pid, uintptr_t target, int depth, int maxOffset) {
    LinuxProcessHandle proc(pid);
    PointerScanner scanner;
    PointerScanConfig config;
    config.targetAddress = target;
    config.maxDepth = depth;
    config.maxOffset = maxOffset;

    printf("Pointer scan: PID %d, target 0x%lx, depth %d, offset %d\n", pid, target, depth, maxOffset);
    printf("Building reverse pointer map...\n");

    auto results = scanner.scan(proc, config);
    printf("Found %zu pointer paths:\n\n", results.size());

    for (size_t i = 0; i < std::min(results.size(), size_t(50)); ++i) {
        auto& p = results[i];
        auto current = PointerScanner::dereference(proc, p);
        printf("  %s", p.toString().c_str());
        if (current) printf("  -> 0x%lx", current);
        printf("\n");
    }
    if (results.size() > 50) printf("  ... and %zu more\n", results.size() - 50);
    return 0;
}

static int cmd_deref(pid_t pid, int argc, char** argv) {
    // cescan deref <pid> <module+offset> <off1> <off2> ...
    if (argc < 1) { fprintf(stderr, "Usage: cescan deref <pid> <module+offset> [off1] [off2] ...\n"); return 1; }

    LinuxProcessHandle proc(pid);
    PointerPath path;

    // Parse module+offset
    std::string base = argv[0];
    auto plus = base.find('+');
    if (plus != std::string::npos) {
        path.module = base.substr(0, plus);
        path.baseOffset = strtoul(base.substr(plus + 1).c_str(), nullptr, 16);
    } else {
        path.module = base;
        path.baseOffset = 0;
    }

    // Parse offsets
    for (int i = 1; i < argc; ++i)
        path.offsets.push_back((int32_t)strtol(argv[i], nullptr, 16));

    // Find module base
    auto modules = proc.modules();
    for (auto& m : modules) {
        if (m.name == path.module) { path.moduleBase = m.base; break; }
    }

    auto addr = PointerScanner::dereference(proc, path);
    printf("Path: %s\n", path.toString().c_str());
    printf("Result: 0x%lx\n", addr);
    return addr ? 0 : 1;
}

static int cmd_asm(pid_t pid, const char* scriptFile, bool disableMode) {
    // Read script
    std::ifstream f(scriptFile);
    if (!f) { fprintf(stderr, "Cannot open: %s\n", scriptFile); return 1; }
    std::string script((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    LinuxProcessHandle proc(pid);
    AutoAssembler autoAsm;

    if (disableMode) {
        printf("Disable mode not supported from CLI (no saved state)\n");
        return 1;
    }

    printf("Executing script on PID %d...\n", pid);
    auto result = autoAsm.execute(proc, script);

    for (auto& msg : result.log)
        printf("  %s\n", msg.c_str());

    if (result.success) {
        printf("SUCCESS: %zu patches, %zu allocations\n",
            result.disableInfo.originals.size(), result.disableInfo.allocs.size());
    } else {
        printf("FAILED: %s\n", result.error.c_str());
        return 1;
    }
    return 0;
}

// ── Main ──

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }

    const char* cmd = argv[1];

    if (!strcmp(cmd, "list")) {
        return cmd_list();
    }
    else if (!strcmp(cmd, "regions") && argc >= 3) {
        return cmd_regions(atoi(argv[2]));
    }
    else if (!strcmp(cmd, "modules") && argc >= 3) {
        return cmd_modules(atoi(argv[2]));
    }
    else if (!strcmp(cmd, "symbols") && argc >= 3) {
        return cmd_symbols(atoi(argv[2]));
    }
    else if (!strcmp(cmd, "read") && argc >= 4) {
        size_t size = (argc >= 5) ? strtoul(argv[4], nullptr, 0) : 64;
        return cmd_read(atoi(argv[2]), strtoul(argv[3], nullptr, 0), size);
    }
    else if (!strcmp(cmd, "write") && argc >= 5) {
        ValueType vt = ValueType::Int32;
        // Check for --type flag after the required args
        for (int i = 5; i < argc - 1; ++i)
            if (!strcmp(argv[i], "--type")) vt = parseType(argv[i+1]);
        return cmd_write(atoi(argv[2]), strtoul(argv[3], nullptr, 0), argv[4], vt);
    }
    else if (!strcmp(cmd, "disasm") && argc >= 4) {
        size_t count = (argc >= 5) ? atoi(argv[4]) : 20;
        return cmd_disasm(atoi(argv[2]), strtoul(argv[3], nullptr, 0), count);
    }
    else if (!strcmp(cmd, "scan") && argc >= 3) {
        pid_t pid = atoi(argv[2]);
        return cmd_scan(pid, argc - 2, argv + 2);
    }
    else if (!strcmp(cmd, "pointerscan") && argc >= 4) {
        pid_t pid = atoi(argv[2]);
        uintptr_t target = strtoul(argv[3], nullptr, 0);
        int depth = (argc >= 5) ? atoi(argv[4]) : 4;
        int offset = (argc >= 6) ? atoi(argv[5]) : 2048;
        return cmd_pointerscan(pid, target, depth, offset);
    }
    else if (!strcmp(cmd, "deref") && argc >= 4) {
        return cmd_deref(atoi(argv[2]), argc - 3, argv + 3);
    }
    else if (!strcmp(cmd, "asm") && argc >= 4) {
        bool disable = false;
        const char* file = argv[3];
        if (argc >= 5 && !strcmp(argv[3], "--disable")) { disable = true; file = argv[4]; }
        return cmd_asm(atoi(argv[2]), file, disable);
    }
    else if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
        usage();
        return 0;
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage();
        return 1;
    }
}
