#include "debug/tracer.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <cstring>

namespace ce {

std::vector<TraceEntry> Tracer::trace(ProcessHandle& proc, Debugger& dbg, const TraceConfig& config) {
    cancelled_.store(false);
    progress_.store(0);

    std::vector<TraceEntry> entries;
    entries.reserve(config.maxSteps);

    pid_t pid = proc.pid();

    // Attach
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0)
        return entries;

    int status;
    waitpid(pid, &status, 0);

    // If we have a start address, set a breakpoint and run until we hit it
    if (config.startAddress) {
        auto r = dbg.setBreakpoint(pid, 0, config.startAddress, 0 /*execute*/, 0 /*1 byte*/);
        if (!r) {
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            return entries;
        }

        ptrace(PTRACE_CONT, pid, nullptr, nullptr);
        waitpid(pid, &status, 0);
        dbg.removeBreakpoint(pid, 0);
    }

    // Single-step loop
    for (int step = 0; step < config.maxSteps && !cancelled_.load(); ++step) {
        progress_.store((float)step / config.maxSteps);

        // Get current state
        auto ctxResult = dbg.getContext(pid);
        if (!ctxResult) break;
        auto& ctx = *ctxResult;

        // Read instruction
        uint8_t instrBuf[16];
        auto readResult = proc.read(ctx.rip, instrBuf, sizeof(instrBuf));
        std::string instrText = "??";
        if (readResult && *readResult > 0) {
            auto insns = disasm_.disassemble(ctx.rip, {instrBuf, *readResult}, 1);
            if (!insns.empty())
                instrText = insns[0].mnemonic + " " + insns[0].operands;
        }

        // Record
        entries.push_back({ctx.rip, instrText, ctx});

        // Check stop conditions
        if (config.stopAddress && ctx.rip == config.stopAddress)
            break;

        if (config.stayInModule && config.moduleBase) {
            if (ctx.rip < config.moduleBase || ctx.rip >= config.moduleEnd)
                break;
        }

        // Step over calls if requested
        if (config.stepOverCalls && instrText.starts_with("call")) {
            // Calculate next instruction address (after the call)
            auto insns = disasm_.disassemble(ctx.rip, {instrBuf, 16}, 1);
            if (!insns.empty()) {
                uintptr_t nextAddr = ctx.rip + insns[0].size;
                // Set breakpoint at return point and continue
                dbg.setBreakpoint(pid, 0, nextAddr, 0, 0);
                ptrace(PTRACE_CONT, pid, nullptr, nullptr);
                waitpid(pid, &status, 0);
                dbg.removeBreakpoint(pid, 0);
                continue;
            }
        }

        // Single step
        auto stepResult = dbg.singleStep(pid);
        if (!stepResult) break;
    }

    progress_.store(1.0f);

    // Detach
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return entries;
}

} // namespace ce
