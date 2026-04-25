#pragma once
/// Auto-assembler engine — parses CE-style scripts and injects code into processes.

#include "platform/process_api.hpp"
#include "arch/assembler.hpp"
#include "scanner/memory_scanner.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

namespace ce {

/// Tracks state needed to disable (undo) an auto-assembler script.
struct DisableInfo {
    struct AllocEntry { std::string name; uintptr_t address; size_t size; };
    struct OriginalBytes { uintptr_t address; std::vector<uint8_t> bytes; };

    std::vector<AllocEntry> allocs;
    std::vector<OriginalBytes> originals;
    std::unordered_map<std::string, uintptr_t> symbols;
};

/// Result of auto-assembler execution.
struct AutoAsmResult {
    bool success = false;
    std::string error;
    DisableInfo disableInfo;
    std::vector<std::string> log; // Execution log messages
};

/// The auto-assembler engine.
class AutoAssembler {
public:
    using CustomCommandHandler = std::function<bool(const std::string& args,
        std::vector<std::string>& outputLines, std::vector<std::string>& log,
        std::string& error)>;
    using ScriptHook = std::function<bool(std::string& code,
        std::vector<std::string>& log, std::string& error)>;

    AutoAssembler() = default;

    /// Execute an auto-assembler script (enable section).
    AutoAsmResult execute(ProcessHandle& proc, const std::string& script);

    /// Execute the disable section of a script, using saved DisableInfo.
    AutoAsmResult disable(ProcessHandle& proc, const std::string& script, const DisableInfo& info);

    /// Syntax check only (no memory modifications).
    AutoAsmResult check(const std::string& script);

    /// Register a global symbol (accessible to scripts).
    void registerSymbol(const std::string& name, uintptr_t address);
    void unregisterSymbol(const std::string& name);
    uintptr_t resolveSymbol(const std::string& name) const;

    /// Register a parser extension command. Command names are case-insensitive.
    void registerCommand(const std::string& name, CustomCommandHandler handler);
    void unregisterCommand(const std::string& name);

    /// Register script transformation hooks for plugin-style preprocessing.
    void addPreprocessorHook(ScriptHook hook);
    void addPostprocessorHook(ScriptHook hook);
    void clearPreprocessorHooks();
    void clearPostprocessorHooks();

private:
    // ── Internal types ──
    struct Alloc { std::string name; size_t size; uintptr_t preferred; uintptr_t address; };
    struct Label { std::string name; uintptr_t address; };
    struct Define { std::string name; std::string value; };
    struct AsmLine { std::string label; std::string code; uintptr_t targetAddr; };
    struct WriteBlock { uintptr_t address; std::vector<uint8_t> bytes; };

    // ── Parsing ──
    std::string extractSection(const std::string& script, const std::string& section);
    bool parseLine(const std::string& line,
        std::vector<Alloc>& allocs, std::vector<Label>& labels,
        std::vector<Define>& defines, std::vector<std::string>& registeredSymbols,
        std::vector<std::string>& asmLines, std::vector<std::string>& log,
        ProcessHandle* proc, std::string& error);

    // ── Resolution ──
    uintptr_t resolveAddress(const std::string& expr,
        const std::vector<Alloc>& allocs, const std::vector<Label>& labels,
        const std::vector<Define>& defines) const;
    std::string substituteSymbols(const std::string& line,
        const std::vector<Alloc>& allocs, const std::vector<Label>& labels,
        const std::vector<Define>& defines) const;

    // ── Global symbol table ──
    std::unordered_map<std::string, uintptr_t> globalSymbols_;
    std::unordered_map<std::string, DisableInfo::AllocEntry> knownAllocations_;
    std::unordered_map<std::string, CustomCommandHandler> customCommands_;
    std::vector<ScriptHook> preprocessorHooks_;
    std::vector<ScriptHook> postprocessorHooks_;
    Assembler asm64_{AsmArch::X86_64};
};

} // namespace ce
