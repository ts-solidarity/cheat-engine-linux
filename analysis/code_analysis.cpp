#include "analysis/code_analysis.hpp"
#include <cstring>
#include <algorithm>

namespace ce {

std::vector<CodeRef> CodeAnalyzer::dissectModule(ProcessHandle& proc, const ModuleInfo& module) {
    std::vector<CodeRef> refs;

    // Read executable sections of the module
    auto regions = proc.queryRegions();
    for (auto& r : regions) {
        if (r.base < module.base || r.base >= module.base + module.size) continue;
        if (!(r.protection & MemProt::Exec)) continue;

        std::vector<uint8_t> buf(r.size);
        auto rr = proc.read(r.base, buf.data(), r.size);
        if (!rr || *rr == 0) continue;

        auto insns = disasm_.disassemble(r.base, {buf.data(), *rr}, 0);
        for (auto& inst : insns) {
            // CALL instructions
            if (inst.mnemonic == "call") {
                CodeRef ref;
                ref.address = inst.address;
                ref.type = RefType::Call;
                ref.text = inst.mnemonic + " " + inst.operands;
                // Try to parse target address from operands
                try {
                    ref.target = std::stoull(inst.operands, nullptr, 16);
                } catch (...) {
                    ref.target = 0;
                }
                if (ref.target) refs.push_back(ref);
            }
            // JMP instructions
            else if (inst.mnemonic == "jmp" || inst.mnemonic[0] == 'j') {
                CodeRef ref;
                ref.address = inst.address;
                ref.type = RefType::Jump;
                ref.text = inst.mnemonic + " " + inst.operands;
                try { ref.target = std::stoull(inst.operands, nullptr, 16); } catch (...) { ref.target = 0; }
                if (ref.target) refs.push_back(ref);
            }
            // LEA with RIP-relative → possible string reference
            else if (inst.mnemonic == "lea" && inst.operands.find("rip") != std::string::npos) {
                // The target is the effective address
                // Capstone computes it for us in the operands like "rax, [rip + 0x1234]"
                // We need the actual computed address
                // For now, mark it as a potential string ref — resolve later
                CodeRef ref;
                ref.address = inst.address;
                ref.type = RefType::String;
                ref.text = inst.mnemonic + " " + inst.operands;
                ref.target = 0; // Would need Capstone detail mode to get the computed address
                refs.push_back(ref);
            }
        }
    }

    return refs;
}

std::vector<CodeRef> CodeAnalyzer::findReferencedStrings(ProcessHandle& proc, const ModuleInfo& module) {
    auto allRefs = dissectModule(proc, module);
    std::vector<CodeRef> strings;
    for (auto& ref : allRefs) {
        if (ref.type == RefType::String || ref.type == RefType::Call) continue;
        // Check if the target points to a readable string
        if (ref.target) {
            char buf[128] = {};
            auto rr = proc.read(ref.target, buf, sizeof(buf) - 1);
            if (rr && *rr > 4) {
                // Check if it looks like a printable string
                bool isString = true;
                int printable = 0;
                for (int j = 0; j < (int)*rr && buf[j]; ++j) {
                    if (buf[j] >= 32 && buf[j] < 127) ++printable;
                    else if (buf[j] != 0) { isString = false; break; }
                }
                if (isString && printable >= 4) {
                    ref.type = RefType::String;
                    ref.text = std::string(buf, strnlen(buf, sizeof(buf)));
                    strings.push_back(ref);
                }
            }
        }
    }
    return strings;
}

std::vector<CodeCave> CodeAnalyzer::findCodeCaves(ProcessHandle& proc, const ModuleInfo& module, size_t minSize) {
    std::vector<CodeCave> caves;
    auto regions = proc.queryRegions();

    for (auto& r : regions) {
        if (r.base < module.base || r.base >= module.base + module.size) continue;
        if (!(r.protection & MemProt::Exec)) continue;

        std::vector<uint8_t> buf(r.size);
        auto rr = proc.read(r.base, buf.data(), r.size);
        if (!rr || *rr == 0) continue;

        size_t runStart = 0;
        bool inRun = false;

        for (size_t i = 0; i < *rr; ++i) {
            bool isEmpty = (buf[i] == 0x00 || buf[i] == 0xCC);
            if (isEmpty && !inRun) {
                runStart = i;
                inRun = true;
            } else if (!isEmpty && inRun) {
                size_t runLen = i - runStart;
                if (runLen >= minSize)
                    caves.push_back({r.base + runStart, runLen});
                inRun = false;
            }
        }
        if (inRun) {
            size_t runLen = *rr - runStart;
            if (runLen >= minSize)
                caves.push_back({r.base + runStart, runLen});
        }
    }

    return caves;
}

} // namespace ce
