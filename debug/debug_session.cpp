#include "debug/debug_session.hpp"
#include "arch/disassembler.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <cstring>
#include <chrono>
#include <cerrno>
#include <unistd.h>

namespace ce {

DebugSession::~DebugSession() {
    if (attached_) detach();
}

bool DebugSession::attach(pid_t pid, ProcessHandle* proc) {
    if (attached_) return false;
    pid_ = pid;
    proc_ = proc;

    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0)
        return false;

    int status;
    waitpid(pid, &status, 0);
    attached_ = true;
    stopped_ = true;

    // Get initial context
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) >= 0) {
        std::lock_guard lock(contextMutex_);
        stopContext_.rip = regs.rip;
        stopContext_.rsp = regs.rsp;
        stopContext_.rax = regs.rax;
    }

    eventThread_ = std::thread(&DebugSession::eventLoop, this);
    return true;
}

void DebugSession::detach() {
    if (!attached_.exchange(false)) return;

    if (eventThread_.joinable()) {
        if (eventThread_.get_id() == std::this_thread::get_id())
            eventThread_.detach();
        else
            eventThread_.join();
    }

    // Remove all software breakpoints
    {
        std::lock_guard lock(bpMutex_);
        for (auto& [addr, bp] : softBreakpoints_) {
            if (bp.active && proc_)
                proc_->write(addr, &bp.originalByte, 1);
        }
        softBreakpoints_.clear();
    }

    ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
    stopped_ = false;
}

int DebugSession::setSoftwareBreakpoint(uintptr_t address) {
    std::lock_guard lock(bpMutex_);

    // Check if already set
    auto it = softBreakpoints_.find(address);
    if (it != softBreakpoints_.end()) return it->second.id;

    // Read original byte
    uint8_t origByte;
    auto r = proc_->read(address, &origByte, 1);
    if (!r) return -1;

    // Write int3 (0xCC)
    uint8_t int3 = 0xCC;
    proc_->write(address, &int3, 1);

    int id = nextSoftBpId_++;
    softBreakpoints_[address] = {id, address, origByte, true};
    return id;
}

void DebugSession::removeSoftwareBreakpoint(int id) {
    std::lock_guard lock(bpMutex_);
    for (auto it = softBreakpoints_.begin(); it != softBreakpoints_.end(); ++it) {
        if (it->second.id == id) {
            if (it->second.active && proc_)
                proc_->write(it->first, &it->second.originalByte, 1);
            softBreakpoints_.erase(it);
            return;
        }
    }
}

void DebugSession::continueExecution() {
    if (!attached_ || !stopped_) return;
    stopped_ = false;
    if (ptrace(PTRACE_CONT, pid_, nullptr, nullptr) < 0)
        stopped_ = true;
}

void DebugSession::eventLoop() {
    while (attached_.load()) {
        int status = 0;
        pid_t waited = waitpid(pid_, &status, WNOHANG);
        if (waited == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        if (waited < 0) {
            if (errno == ECHILD) {
                attached_ = false;
                stopped_ = false;
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        stopped_ = true;

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);

            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid_, nullptr, &regs);

            {
                std::lock_guard lock(contextMutex_);
                stopContext_.rip = regs.rip;
                stopContext_.rsp = regs.rsp;
                stopContext_.rax = regs.rax;
                stopContext_.rbx = regs.rbx;
                stopContext_.rcx = regs.rcx;
                stopContext_.rdx = regs.rdx;
                stopContext_.rsi = regs.rsi;
                stopContext_.rdi = regs.rdi;
                stopContext_.rbp = regs.rbp;
                stopContext_.rflags = regs.eflags;
            }

            if (sig == SIGTRAP) {
                // Check if we hit a software breakpoint (RIP is one past the int3)
                uintptr_t bpAddr = regs.rip - 1;
                std::lock_guard lock(bpMutex_);
                auto it = softBreakpoints_.find(bpAddr);
                if (it != softBreakpoints_.end()) {
                    // Restore original byte
                    proc_->write(bpAddr, &it->second.originalByte, 1);
                    // Back up RIP to the breakpoint address
                    regs.rip = bpAddr;
                    ptrace(PTRACE_SETREGS, pid_, nullptr, &regs);

                    DebugEvent evt;
                    evt.type = DebugEventType::BreakpointHit;
                    evt.tid = pid_;
                    evt.address = bpAddr;
                    evt.signal = sig;
                    evt.context = stopContext_;
                    if (eventCb_) eventCb_(evt);

                    // Re-set the breakpoint after single-stepping past it
                    ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr);
                    waitpid(pid_, &status, 0);
                    uint8_t int3 = 0xCC;
                    proc_->write(bpAddr, &int3, 1);
                    continue;
                }
            }

            DebugEvent evt;
            evt.type = (sig == SIGTRAP) ? DebugEventType::SingleStep : DebugEventType::SignalReceived;
            evt.tid = pid_;
            evt.address = regs.rip;
            evt.signal = sig;
            evt.context = stopContext_;
            if (eventCb_) eventCb_(evt);
        } else if (WIFEXITED(status) || WIFSIGNALED(status)) {
            DebugEvent evt;
            evt.type = DebugEventType::ProcessExited;
            evt.tid = pid_;
            if (eventCb_) eventCb_(evt);
            attached_ = false;
            stopped_ = false;
        }
    }
}

void DebugSession::step(StepMode mode, uintptr_t targetAddress) {
    if (!attached_ || !stopped_) return;

    switch (mode) {
        case StepMode::Into:
            ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr);
            break;

        case StepMode::Over: {
            // Read current instruction to check if it's a CALL
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid_, nullptr, &regs);
            uint8_t buf[16];
            proc_->read(regs.rip, buf, sizeof(buf));
            Disassembler dis(Arch::X86_64);
            auto insns = dis.disassemble(regs.rip, {buf, 16}, 1);
            if (!insns.empty() && insns[0].mnemonic == "call") {
                // Set temp breakpoint at next instruction
                uintptr_t nextAddr = regs.rip + insns[0].size;
                int tmpBp = setSoftwareBreakpoint(nextAddr);
                ptrace(PTRACE_CONT, pid_, nullptr, nullptr);
                int status;
                waitpid(pid_, &status, 0);
                removeSoftwareBreakpoint(tmpBp);
            } else {
                ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr);
            }
            break;
        }

        case StepMode::Out: {
            // Set breakpoint at return address (read [RSP])
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid_, nullptr, &regs);
            uintptr_t retAddr = 0;
            proc_->read(regs.rsp, &retAddr, sizeof(retAddr));
            if (retAddr) {
                int tmpBp = setSoftwareBreakpoint(retAddr);
                ptrace(PTRACE_CONT, pid_, nullptr, nullptr);
                int status;
                waitpid(pid_, &status, 0);
                removeSoftwareBreakpoint(tmpBp);
            }
            break;
        }

        case StepMode::RunToCursor:
            if (targetAddress) {
                int tmpBp = setSoftwareBreakpoint(targetAddress);
                ptrace(PTRACE_CONT, pid_, nullptr, nullptr);
                int status;
                waitpid(pid_, &status, 0);
                removeSoftwareBreakpoint(tmpBp);
            }
            break;
    }

    // Update context after step
    int status;
    waitpid(pid_, &status, WNOHANG);
    stopped_ = true;

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) >= 0) {
        std::lock_guard lock(contextMutex_);
        stopContext_.rip = regs.rip;
        stopContext_.rsp = regs.rsp;
        stopContext_.rax = regs.rax;
        stopContext_.rbx = regs.rbx;
        stopContext_.rcx = regs.rcx;
        stopContext_.rdx = regs.rdx;
        stopContext_.rsi = regs.rsi;
        stopContext_.rdi = regs.rdi;
        stopContext_.rbp = regs.rbp;
        stopContext_.rflags = regs.eflags;
    }
}

CpuContext DebugSession::getStopContext() const {
    std::lock_guard lock(contextMutex_);
    return stopContext_;
}

} // namespace ce
