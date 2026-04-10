#include "debug/code_finder.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <algorithm>
#include <cstring>

namespace ce {

bool CodeFinder::start(ProcessHandle& proc, Debugger& dbg, uintptr_t address, bool writesOnly) {
    if (running_) return false;

    proc_ = &proc;
    dbg_ = &dbg;
    targetAddress_ = address;
    writesOnly_ = writesOnly;
    stopRequested_ = false;
    running_ = true;

    monitorThread_ = std::thread(&CodeFinder::monitorLoop, this);
    return true;
}

void CodeFinder::stop() {
    stopRequested_ = true;
    if (monitorThread_.joinable())
        monitorThread_.join();
    running_ = false;
}

std::vector<CodeFinderResult> CodeFinder::results() const {
    std::lock_guard lock(resultsMutex_);
    std::vector<CodeFinderResult> res;
    res.reserve(resultsMap_.size());
    for (auto& [_, r] : resultsMap_)
        res.push_back(r);
    std::sort(res.begin(), res.end(),
        [](const CodeFinderResult& a, const CodeFinderResult& b) { return a.hitCount > b.hitCount; });
    return res;
}

void CodeFinder::clearResults() {
    std::lock_guard lock(resultsMutex_);
    resultsMap_.clear();
}

void CodeFinder::monitorLoop() {
    pid_t pid = proc_->pid();

    // Attach
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
        running_ = false;
        return;
    }
    int status;
    waitpid(pid, &status, 0);

    // Set a hardware watchpoint on the target address
    // DR0 for our watchpoint, type = 1 (write) or 3 (read/write)
    int bpType = writesOnly_ ? 1 : 3;
    int bpSize = 3; // 4 bytes (encoded as 3 for x86)

    auto setResult = dbg_->setBreakpoint(pid, 0, targetAddress_, bpType, bpSize);
    if (!setResult) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        running_ = false;
        return;
    }

    // Continue and wait for watchpoint hits
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);

    while (!stopRequested_) {
        int w = waitpid(pid, &status, WNOHANG);
        if (w <= 0) {
            usleep(1000); // 1ms poll
            continue;
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);

            if (sig == SIGTRAP) {
                // Watchpoint hit — get the instruction that caused it
                auto ctxResult = dbg_->getContext(pid);
                if (ctxResult) {
                    auto& ctx = *ctxResult;
                    uintptr_t rip = ctx.rip;

                    // Read instruction bytes at RIP
                    uint8_t instrBuf[16];
                    auto readResult = proc_->read(rip, instrBuf, sizeof(instrBuf));

                    std::string instrText;
                    std::vector<uint8_t> instrBytes;
                    if (readResult && *readResult > 0) {
                        auto insns = disasm_.disassemble(rip, {instrBuf, *readResult}, 1);
                        if (!insns.empty()) {
                            instrText = insns[0].mnemonic + " " + insns[0].operands;
                            instrBytes = insns[0].bytes;
                        }
                    }

                    // Record the hit
                    {
                        std::lock_guard lock(resultsMutex_);
                        auto& entry = resultsMap_[rip];
                        if (entry.hitCount == 0) {
                            entry.instructionAddress = rip;
                            entry.instructionText = instrText;
                            entry.instructionBytes = instrBytes;
                        }
                        entry.hitCount++;
                    }
                }

                // Continue (auto-resume — don't break to user)
                ptrace(PTRACE_CONT, pid, nullptr, nullptr);
            } else {
                // Not our signal — forward it
                ptrace(PTRACE_CONT, pid, nullptr, (void*)(uintptr_t)sig);
            }
        } else if (WIFEXITED(status) || WIFSIGNALED(status)) {
            break; // Process died
        }
    }

    // Clean up — remove watchpoint and detach
    dbg_->removeBreakpoint(pid, 0);
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    running_ = false;
}

} // namespace ce
