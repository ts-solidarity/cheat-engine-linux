#include "platform/linux/linux_process.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <cstring>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/user.h>
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

// Execute a syscall in the target process via ptrace
static int64_t remoteSyscall(pid_t pid, uint64_t nr,
    uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6)
{
    struct user_regs_struct oldRegs, regs;

    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0)
        return -1;
    int status;
    waitpid(pid, &status, 0);

    if (ptrace(PTRACE_GETREGS, pid, nullptr, &oldRegs) < 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return -1;
    }

    regs = oldRegs;
    regs.rax = nr;
    regs.rdi = a1; regs.rsi = a2; regs.rdx = a3;
    regs.r10 = a4; regs.r8 = a5; regs.r9 = a6;

    // Save and replace instruction at RIP with syscall (0F 05)
    uint64_t origInstr = ptrace(PTRACE_PEEKTEXT, pid, (void*)oldRegs.rip, nullptr);
    ptrace(PTRACE_POKETEXT, pid, (void*)oldRegs.rip, (void*)((origInstr & ~0xFFFFULL) | 0x050fULL));
    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
    waitpid(pid, &status, 0);

    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    int64_t result = regs.rax;

    ptrace(PTRACE_POKETEXT, pid, (void*)oldRegs.rip, (void*)origInstr);
    ptrace(PTRACE_SETREGS, pid, nullptr, &oldRegs);
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return result;
}

Result<uintptr_t> LinuxProcessHandle::allocate(size_t size, MemProt protection, uintptr_t preferredBase) {
    int prot = 0;
    if (protection & MemProt::Read)  prot |= 1; // PROT_READ
    if (protection & MemProt::Write) prot |= 2; // PROT_WRITE
    if (protection & MemProt::Exec)  prot |= 4; // PROT_EXEC

    int flags = 0x22; // MAP_PRIVATE | MAP_ANONYMOUS
    size_t allocSize = (size + 4095) & ~4095ULL; // Page-align

    // Try near-allocation first (within ±2GB for RIP-relative addressing)
    if (preferredBase) {
        auto regions = queryRegions();
        constexpr int64_t MAX_DIST = 0x7FFF0000LL; // ~2GB

        // Search for gaps near preferredBase
        uintptr_t prevEnd = 0;
        for (auto& r : regions) {
            uintptr_t gapStart = prevEnd;
            uintptr_t gapEnd = r.base;

            if (gapEnd > gapStart && (gapEnd - gapStart) >= allocSize) {
                // Check if this gap is within ±2GB of preferred
                int64_t distStart = (int64_t)gapStart - (int64_t)preferredBase;
                int64_t distEnd = (int64_t)(gapEnd - allocSize) - (int64_t)preferredBase;

                if (std::abs(distStart) < MAX_DIST || std::abs(distEnd) < MAX_DIST) {
                    // Pick the closest address within range
                    uintptr_t allocAddr = gapStart;
                    if ((int64_t)gapStart < (int64_t)preferredBase - MAX_DIST)
                        allocAddr = (uintptr_t)((int64_t)preferredBase - MAX_DIST);
                    if (allocAddr < gapStart) allocAddr = gapStart;
                    allocAddr = (allocAddr + 4095) & ~4095ULL; // Page-align

                    if (allocAddr + allocSize <= gapEnd) {
                        int64_t result = remoteSyscall(pid_, 9 /*__NR_mmap*/,
                            allocAddr, allocSize, prot, flags | 0x10 /*MAP_FIXED_NOREPLACE*/, -1, 0);
                        if (result > 0 && result != -1)
                            return (uintptr_t)result;
                    }
                }
            }
            prevEnd = r.base + r.size;
        }
    }

    // Fallback: allocate anywhere
    int64_t result = remoteSyscall(pid_, 9 /*__NR_mmap*/,
        0, allocSize, prot, flags, -1, 0);

    if (result <= 0 || result == -1)
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));

    return (uintptr_t)result;
}

Result<void> LinuxProcessHandle::free(uintptr_t address, size_t size) {
    size_t freeSize = (size + 4095) & ~4095ULL;
    int64_t result = remoteSyscall(pid_, 11 /*__NR_munmap*/, address, freeSize, 0, 0, 0, 0);
    if (result < 0)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    return {};
}

Result<void> LinuxProcessHandle::protect(uintptr_t address, size_t size, MemProt newProtection) {
    int prot = 0;
    if (newProtection & MemProt::Read)  prot |= 1;
    if (newProtection & MemProt::Write) prot |= 2;
    if (newProtection & MemProt::Exec)  prot |= 4;
    size_t protSize = (size + 4095) & ~4095ULL;
    int64_t result = remoteSyscall(pid_, 10 /*__NR_mprotect*/, address, protSize, prot, 0, 0, 0);
    if (result < 0)
        return std::unexpected(std::make_error_code(std::errc::permission_denied));
    return {};
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
