#include "platform/linux/injector.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <cstring>
#include <cerrno>

namespace ce::os {

// Syscall numbers for x86_64
static constexpr uint64_t NR_MMAP = 9;
static constexpr uint64_t NR_MUNMAP = 11;

// Execute a syscall in the target process via ptrace
static int64_t remoteSyscall(pid_t pid, uint64_t nr,
    uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6)
{
    struct user_regs_struct oldRegs, regs;

    if (ptrace(PTRACE_GETREGS, pid, nullptr, &oldRegs) < 0)
        return -1;

    regs = oldRegs;
    regs.rax = nr;
    regs.rdi = a1;
    regs.rsi = a2;
    regs.rdx = a3;
    regs.r10 = a4;
    regs.r8  = a5;
    regs.r9  = a6;

    // Save original instruction and write syscall
    uint64_t origInstr;
    uint64_t syscallInstr = 0x050f; // syscall
    origInstr = ptrace(PTRACE_PEEKTEXT, pid, (void*)oldRegs.rip, nullptr);
    ptrace(PTRACE_POKETEXT, pid, (void*)oldRegs.rip, (void*)((origInstr & ~0xFFFF) | syscallInstr));

    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);

    int status;
    waitpid(pid, &status, 0);

    // Get result
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    int64_t result = regs.rax;

    // Restore
    ptrace(PTRACE_POKETEXT, pid, (void*)oldRegs.rip, (void*)origInstr);
    ptrace(PTRACE_SETREGS, pid, nullptr, &oldRegs);

    return result;
}

// Call a function in the target process
static uint64_t remoteCall(pid_t pid, uintptr_t funcAddr, uintptr_t arg1) {
    struct user_regs_struct oldRegs, regs;

    if (ptrace(PTRACE_GETREGS, pid, nullptr, &oldRegs) < 0)
        return (uint64_t)-1;

    regs = oldRegs;
    regs.rip = funcAddr;
    regs.rdi = arg1;
    regs.rsi = 1; // RTLD_LAZY
    regs.rsp -= 128; // Red zone
    regs.rsp &= ~0xFULL; // Align

    // Push return address (a breakpoint trap)
    regs.rsp -= 8;
    ptrace(PTRACE_POKETEXT, pid, (void*)regs.rsp, (void*)0xCCCCCCCCCCCCCCCCULL);

    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);

    int status;
    waitpid(pid, &status, 0);

    // Get return value
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    uint64_t result = regs.rax;

    // Restore
    ptrace(PTRACE_SETREGS, pid, nullptr, &oldRegs);

    return result;
}

std::expected<uintptr_t, std::string>
injectLibrary(ProcessHandle& proc, SymbolResolver& resolver, const std::string& soPath) {
    pid_t pid = proc.pid();

    // Find dlopen in target's libc
    uintptr_t dlopenAddr = resolver.lookup("__libc_dlopen_mode");
    if (!dlopenAddr) dlopenAddr = resolver.lookup("dlopen");
    if (!dlopenAddr)
        return std::unexpected("dlopen not found in target process symbols");

    // Attach
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0)
        return std::unexpected(std::string("ptrace attach failed: ") + strerror(errno));

    int status;
    waitpid(pid, &status, 0);

    // Allocate memory in target for the path string
    size_t pathLen = soPath.size() + 1;
    size_t allocSize = (pathLen + 4095) & ~4095; // Page-aligned

    int64_t remoteMem = remoteSyscall(pid, NR_MMAP,
        0, allocSize, 3 /*PROT_READ|PROT_WRITE*/, 0x22 /*MAP_PRIVATE|MAP_ANONYMOUS*/, -1, 0);

    if (remoteMem <= 0 || remoteMem == -1) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return std::unexpected("Failed to allocate memory in target");
    }

    // Write the path string
    const char* pathStr = soPath.c_str();
    for (size_t i = 0; i < pathLen; i += sizeof(long)) {
        long word = 0;
        memcpy(&word, pathStr + i, std::min(sizeof(long), pathLen - i));
        ptrace(PTRACE_POKETEXT, pid, (void*)(remoteMem + i), (void*)word);
    }

    // Call dlopen(path, RTLD_LAZY)
    uint64_t handle = remoteCall(pid, dlopenAddr, remoteMem);

    // Free the path memory
    remoteSyscall(pid, NR_MUNMAP, remoteMem, allocSize, 0, 0, 0, 0);

    // Detach
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);

    if (handle == 0 || handle == (uint64_t)-1)
        return std::unexpected("dlopen returned NULL in target process");

    return (uintptr_t)handle;
}

} // namespace ce::os
