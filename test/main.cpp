#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "core/ct_file.hpp"

#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <filesystem>
#include <csignal>
#include <unistd.h>
#include <sys/wait.h>

using namespace ce;
using namespace ce::os;

static void test_cheat_table_json() {
    printf("\n── Test: CheatTable JSON Round Trip ──\n");

    CheatTable table;
    table.gameName = "Example Game";
    table.author = "cecore";

    CheatEntry entry;
    entry.id = 7;
    entry.description = "Health \"current\"";
    entry.address = 0x1234;
    entry.type = ValueType::Int32;
    entry.value = "100\n200";
    entry.active = true;
    entry.autoAsmScript = "[ENABLE]\nassert(1234, 90)\n";
    table.entries.push_back(entry);

    auto path = std::filesystem::temp_directory_path() /
        ("cecore-table-" + std::to_string(getpid()) + ".json");

    if (!table.saveJson(path.string())) {
        printf("  Save FAILED\n");
        return;
    }

    CheatTable loaded;
    bool ok = loaded.loadJson(path.string());
    std::filesystem::remove(path);

    bool matches = ok &&
        loaded.gameName == table.gameName &&
        loaded.author == table.author &&
        loaded.entries.size() == 1 &&
        loaded.entries[0].id == entry.id &&
        loaded.entries[0].description == entry.description &&
        loaded.entries[0].address == entry.address &&
        loaded.entries[0].type == entry.type &&
        loaded.entries[0].value == entry.value &&
        loaded.entries[0].active == entry.active &&
        loaded.entries[0].autoAsmScript == entry.autoAsmScript;

    printf("  JSON round trip: %s\n", matches ? "OK" : "FAILED");
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
