#pragma once
/// Code analysis — dissect modules for functions, strings, code caves.

#include "platform/process_api.hpp"
#include "arch/disassembler.hpp"
#include "symbols/elf_symbols.hpp"
#include <vector>
#include <string>

namespace ce {

enum class RefType { Call, Jump, String, Function };

struct CodeRef {
    uintptr_t address;      // Address of the instruction
    uintptr_t target;       // Target address (call/jump target, string address)
    RefType type;
    std::string text;       // Instruction text or string content
};

struct CodeCave {
    uintptr_t address;
    size_t size;
};

class CodeAnalyzer {
public:
    /// Dissect a module — find all calls, jumps, string references.
    std::vector<CodeRef> dissectModule(ProcessHandle& proc, const ModuleInfo& module);

    /// Find referenced strings (LEA instructions pointing to readable data).
    std::vector<CodeRef> findReferencedStrings(ProcessHandle& proc, const ModuleInfo& module);

    /// Find direct call targets inside a module.
    std::vector<CodeRef> findReferencedFunctions(ProcessHandle& proc, const ModuleInfo& module);

    /// Find code caves (runs of 0x00 or 0xCC bytes).
    std::vector<CodeCave> findCodeCaves(ProcessHandle& proc, const ModuleInfo& module, size_t minSize = 16);

private:
    Disassembler disasm_{Arch::X86_64};
};

} // namespace ce
