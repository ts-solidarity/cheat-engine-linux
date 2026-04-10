#include "platform/linux/ptrace_wrapper.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <signal.h>
#include <cerrno>
#include <cstring>

namespace ce::os {

Error LinuxDebugger::errFromErrno() {
    return std::error_code(errno, std::system_category());
}

LinuxDebugger::~LinuxDebugger() {
    if (attached_) detach();
}

Result<void> LinuxDebugger::attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0)
        return std::unexpected(errFromErrno());

    int status;
    waitpid(pid, &status, 0);

    pid_ = pid;
    attached_ = true;
    return {};
}

Result<void> LinuxDebugger::detach() {
    if (!attached_) return {};

    if (ptrace(PTRACE_DETACH, pid_, nullptr, nullptr) < 0)
        return std::unexpected(errFromErrno());

    attached_ = false;
    pid_ = 0;
    return {};
}

Result<CpuContext> LinuxDebugger::getContext(pid_t tid) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) < 0)
        return std::unexpected(errFromErrno());

    CpuContext ctx{};
    ctx.rax = regs.rax; ctx.rbx = regs.rbx;
    ctx.rcx = regs.rcx; ctx.rdx = regs.rdx;
    ctx.rsi = regs.rsi; ctx.rdi = regs.rdi;
    ctx.rbp = regs.rbp; ctx.rsp = regs.rsp;
    ctx.r8  = regs.r8;  ctx.r9  = regs.r9;
    ctx.r10 = regs.r10; ctx.r11 = regs.r11;
    ctx.r12 = regs.r12; ctx.r13 = regs.r13;
    ctx.r14 = regs.r14; ctx.r15 = regs.r15;
    ctx.rip = regs.rip;
    ctx.rflags = regs.eflags;
    ctx.cs = regs.cs; ctx.ss = regs.ss;
    ctx.ds = regs.ds; ctx.es = regs.es;
    ctx.fs = regs.fs; ctx.gs = regs.gs;
    return ctx;
}

Result<void> LinuxDebugger::setContext(pid_t tid, const CpuContext& ctx) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) < 0)
        return std::unexpected(errFromErrno());

    regs.rax = ctx.rax; regs.rbx = ctx.rbx;
    regs.rcx = ctx.rcx; regs.rdx = ctx.rdx;
    regs.rsi = ctx.rsi; regs.rdi = ctx.rdi;
    regs.rbp = ctx.rbp; regs.rsp = ctx.rsp;
    regs.r8  = ctx.r8;  regs.r9  = ctx.r9;
    regs.r10 = ctx.r10; regs.r11 = ctx.r11;
    regs.r12 = ctx.r12; regs.r13 = ctx.r13;
    regs.r14 = ctx.r14; regs.r15 = ctx.r15;
    regs.rip = ctx.rip;
    regs.eflags = ctx.rflags;
    regs.cs = ctx.cs; regs.ss = ctx.ss;
    regs.ds = ctx.ds; regs.es = ctx.es;
    regs.fs = ctx.fs; regs.gs = ctx.gs;

    if (ptrace(PTRACE_SETREGS, tid, nullptr, &regs) < 0)
        return std::unexpected(errFromErrno());
    return {};
}

Result<void> LinuxDebugger::suspend(pid_t tid) {
    // tkill sends signal to specific thread
    if (syscall(SYS_tkill, tid, SIGSTOP) < 0)
        return std::unexpected(errFromErrno());
    return {};
}

Result<void> LinuxDebugger::resume(pid_t tid) {
    if (syscall(SYS_tkill, tid, SIGCONT) < 0)
        return std::unexpected(errFromErrno());
    return {};
}

Result<void> LinuxDebugger::singleStep(pid_t tid) {
    if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) < 0)
        return std::unexpected(errFromErrno());

    int status;
    waitpid(tid, &status, 0);
    return {};
}

Result<void> LinuxDebugger::setBreakpoint(pid_t tid, int reg, uintptr_t address, int type, int size) {
    if (reg < 0 || reg > 3)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));

    // Set DR[reg] address
    size_t dr_offset = offsetof(struct user, u_debugreg) + reg * sizeof(long);
    if (ptrace(PTRACE_POKEUSER, tid, dr_offset, address) < 0)
        return std::unexpected(errFromErrno());

    // Read current DR7
    size_t dr7_offset = offsetof(struct user, u_debugreg) + 7 * sizeof(long);
    long dr7 = ptrace(PTRACE_PEEKUSER, tid, dr7_offset, nullptr);

    // Enable breakpoint in DR7
    // Bits: local enable at bit (reg*2), condition at bits (16 + reg*4), length at bits (18 + reg*4)
    dr7 |= (1L << (reg * 2));                 // Local enable
    dr7 &= ~(0xFL << (16 + reg * 4));         // Clear condition+length bits
    dr7 |= ((long)(type & 0x3) << (16 + reg * 4));   // Condition (0=exec, 1=write, 3=rw)
    dr7 |= ((long)(size & 0x3) << (18 + reg * 4));   // Length (0=1byte, 1=2byte, 3=4byte)

    if (ptrace(PTRACE_POKEUSER, tid, dr7_offset, dr7) < 0)
        return std::unexpected(errFromErrno());

    return {};
}

Result<void> LinuxDebugger::removeBreakpoint(pid_t tid, int reg) {
    if (reg < 0 || reg > 3)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));

    // Clear DR[reg] address
    size_t dr_offset = offsetof(struct user, u_debugreg) + reg * sizeof(long);
    if (ptrace(PTRACE_POKEUSER, tid, dr_offset, 0) < 0)
        return std::unexpected(errFromErrno());

    // Disable in DR7
    size_t dr7_offset = offsetof(struct user, u_debugreg) + 7 * sizeof(long);
    long dr7 = ptrace(PTRACE_PEEKUSER, tid, dr7_offset, nullptr);
    dr7 &= ~(1L << (reg * 2));           // Disable local enable
    dr7 &= ~(0xFL << (16 + reg * 4));    // Clear condition+length

    if (ptrace(PTRACE_POKEUSER, tid, dr7_offset, dr7) < 0)
        return std::unexpected(errFromErrno());

    return {};
}

} // namespace ce::os
