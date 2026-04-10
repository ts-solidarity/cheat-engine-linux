#include "platform/linux/linux_process.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <cstring>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <fcntl.h>
#include <cerrno>

namespace ce::os {

namespace fs = std::filesystem;

// ── LinuxProcessHandle ──

LinuxProcessHandle::LinuxProcessHandle(pid_t pid)
    : pid_(pid), is64bit_(detectIs64Bit()) {}

LinuxProcessHandle::~LinuxProcessHandle() = default;

bool LinuxProcessHandle::detectIs64Bit() const {
    auto path = "/proc/" + std::to_string(pid_) + "/exe";
    std::ifstream f(path, std::ios::binary);
    if (!f) return true; // default to 64-bit
    f.seekg(4); // EI_CLASS offset in ELF header
    char elfClass = 0;
    f.read(&elfClass, 1);
    return elfClass != 1; // 1 = ELFCLASS32, 2 = ELFCLASS64
}

Result<size_t> LinuxProcessHandle::read(uintptr_t address, void* buffer, size_t size) {
    struct iovec local  = { buffer,          size };
    struct iovec remote = { (void*)address,  size };

    ssize_t n = process_vm_readv(pid_, &local, 1, &remote, 1, 0);
    if (n < 0)
        return std::unexpected(std::error_code(errno, std::system_category()));
    return static_cast<size_t>(n);
}

Result<size_t> LinuxProcessHandle::write(uintptr_t address, const void* buffer, size_t size) {
    struct iovec local  = { const_cast<void*>(buffer), size };
    struct iovec remote = { (void*)address,            size };

    ssize_t n = process_vm_writev(pid_, &local, 1, &remote, 1, 0);
    if (n < 0)
        return std::unexpected(std::error_code(errno, std::system_category()));
    return static_cast<size_t>(n);
}

MemProt LinuxProcessHandle::parsePerms(const std::string& perms) const {
    auto p = MemProt::None;
    if (perms.size() >= 3) {
        if (perms[0] == 'r') p = p | MemProt::Read;
        if (perms[1] == 'w') p = p | MemProt::Write;
        if (perms[2] == 'x') p = p | MemProt::Exec;
    }
    return p;
}

std::vector<MemoryRegion> LinuxProcessHandle::queryRegions() {
    std::vector<MemoryRegion> regions;
    std::ifstream maps("/proc/" + std::to_string(pid_) + "/maps");
    if (!maps) return regions;

    std::string line;
    while (std::getline(maps, line)) {
        if (line.empty()) continue;

        // Parse: "startaddr-endaddr perms offset dev inode pathname"
        auto dash = line.find('-');
        auto space1 = line.find(' ');
        if (dash == std::string::npos || space1 == std::string::npos) continue;

        MemoryRegion r;
        try {
            r.base = std::stoull(line.substr(0, dash), nullptr, 16);
            auto end = std::stoull(line.substr(dash + 1, space1 - dash - 1), nullptr, 16);
            r.size = end - r.base;
        } catch (...) {
            continue;
        }

        auto perms = line.substr(space1 + 1, 4);
        r.protection = parsePerms(perms);
        r.state = MemState::Committed;

        // Find the path (last field after inode)
        // Format: addr perms offset dev inode [pathname]
        size_t pos = space1 + 1; // past perms start
        int fields = 0;
        while (fields < 4 && pos < line.size()) {
            pos = line.find(' ', pos);
            if (pos == std::string::npos) break;
            while (pos < line.size() && line[pos] == ' ') ++pos;
            ++fields;
        }
        if (pos < line.size()) {
            r.path = line.substr(pos);
            // Trim
            while (!r.path.empty() && r.path.back() == ' ') r.path.pop_back();
        }

        r.type = (!r.path.empty() && r.path[0] == '/') ? MemType::Image : MemType::Private;
        regions.push_back(std::move(r));
    }
    return regions;
}

std::optional<MemoryRegion> LinuxProcessHandle::queryRegion(uintptr_t address) {
    auto regions = queryRegions();
    for (auto& r : regions) {
        if (address >= r.base && address < r.base + r.size)
            return r;
    }
    return std::nullopt;
}

Result<uintptr_t> LinuxProcessHandle::allocate(size_t size, MemProt protection, uintptr_t preferredBase) {
    // Remote mmap via ptrace syscall injection
    int prot = 0;
    if (protection & MemProt::Read)  prot |= 1; // PROT_READ
    if (protection & MemProt::Write) prot |= 2; // PROT_WRITE
    if (protection & MemProt::Exec)  prot |= 4; // PROT_EXEC

    // This would need the ptrace syscall injection mechanism
    // For now, return an error indicating it's not yet implemented
    return std::unexpected(std::make_error_code(std::errc::function_not_supported));
}

Result<void> LinuxProcessHandle::free(uintptr_t address, size_t size) {
    return std::unexpected(std::make_error_code(std::errc::function_not_supported));
}

Result<void> LinuxProcessHandle::protect(uintptr_t address, size_t size, MemProt newProtection) {
    return std::unexpected(std::make_error_code(std::errc::function_not_supported));
}

std::vector<ModuleInfo> LinuxProcessHandle::modules() {
    std::vector<ModuleInfo> mods;
    auto regions = queryRegions();

    // Collapse regions with the same file path into modules
    for (auto& r : regions) {
        if (r.path.empty() || r.path[0] != '/') continue;

        auto it = std::find_if(mods.begin(), mods.end(),
            [&](const ModuleInfo& m) { return m.path == r.path; });

        if (it != mods.end()) {
            // Extend existing module
            auto end = r.base + r.size;
            auto modEnd = it->base + it->size;
            if (r.base < it->base) it->base = r.base;
            if (end > modEnd) it->size = end - it->base;
            else it->size = modEnd - it->base;
        } else {
            ModuleInfo m;
            m.base = r.base;
            m.size = r.size;
            m.path = r.path;
            m.name = fs::path(r.path).filename().string();
            m.is64bit = is64bit_;
            mods.push_back(std::move(m));
        }
    }
    return mods;
}

std::vector<ThreadInfo> LinuxProcessHandle::threads() {
    std::vector<ThreadInfo> tids;
    auto taskDir = "/proc/" + std::to_string(pid_) + "/task";
    try {
        for (auto& entry : fs::directory_iterator(taskDir)) {
            auto name = entry.path().filename().string();
            try {
                ThreadInfo t;
                t.tid = std::stoi(name);
                tids.push_back(t);
            } catch (...) {}
        }
    } catch (...) {}
    return tids;
}

// ── LinuxProcessEnumerator ──

std::vector<ProcessInfo> LinuxProcessEnumerator::list() {
    std::vector<ProcessInfo> procs;
    try {
        for (auto& entry : fs::directory_iterator("/proc")) {
            auto name = entry.path().filename().string();
            pid_t pid;
            try { pid = std::stoi(name); } catch (...) { continue; }
            if (!entry.is_directory()) continue;

            ProcessInfo p;
            p.pid = pid;

            // Read comm for process name
            std::ifstream comm("/proc/" + name + "/comm");
            if (comm) std::getline(comm, p.name);

            // Read exe symlink for path
            try {
                p.path = fs::read_symlink("/proc/" + name + "/exe").string();
            } catch (...) {}

            procs.push_back(std::move(p));
        }
    } catch (...) {}

    std::sort(procs.begin(), procs.end(),
        [](const ProcessInfo& a, const ProcessInfo& b) { return a.pid < b.pid; });
    return procs;
}

std::unique_ptr<ProcessHandle> LinuxProcessEnumerator::open(pid_t pid) {
    return std::make_unique<LinuxProcessHandle>(pid);
}

} // namespace ce::os
