#include "analysis/code_analysis.hpp"
#include <cstring>
#include <algorithm>
#include <charconv>
#include <cctype>
#include <optional>

namespace ce {

namespace {

std::optional<int64_t> parseInteger(std::string_view text) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.remove_prefix(1);
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) text.remove_suffix(1);
    if (text.empty()) return std::nullopt;

    bool neg = false;
    if (text.front() == '+' || text.front() == '-') {
        neg = text.front() == '-';
        text.remove_prefix(1);
        while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.remove_prefix(1);
    }

    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text.remove_prefix(2);
    }

    uint64_t value = 0;
    auto* first = text.data();
    auto* last = text.data() + text.size();
    auto [ptr, ec] = std::from_chars(first, last, value, base);
    if (ec != std::errc{} || ptr != last) return std::nullopt;
    if (neg) return -static_cast<int64_t>(value);
    return static_cast<int64_t>(value);
}

std::optional<uintptr_t> parseDirectTarget(const std::string& operands) {
    auto comma = operands.rfind(',');
    std::string_view target(operands);
    if (comma != std::string::npos)
        target = std::string_view(operands).substr(comma + 1);
    if (target.find('[') != std::string_view::npos)
        return std::nullopt;
    auto parsed = parseInteger(target);
    if (!parsed || *parsed < 0) return std::nullopt;
    return static_cast<uintptr_t>(*parsed);
}

std::optional<uintptr_t> parseRipRelativeTarget(const Instruction& inst) {
    auto rip = inst.operands.find("rip");
    if (rip == std::string::npos) return std::nullopt;

    auto close = inst.operands.find(']', rip);
    auto plus = inst.operands.find('+', rip);
    auto minus = inst.operands.find('-', rip);

    size_t op = std::min(plus == std::string::npos ? inst.operands.size() : plus,
                         minus == std::string::npos ? inst.operands.size() : minus);
    if (op == inst.operands.size() || (close != std::string::npos && op > close))
        return inst.address + inst.size;

    auto end = close == std::string::npos ? inst.operands.size() : close;
    auto disp = parseInteger(std::string_view(inst.operands).substr(op, end - op));
    if (!disp) return std::nullopt;
    return static_cast<uintptr_t>(static_cast<int64_t>(inst.address + inst.size) + *disp);
}

bool readPrintableString(ProcessHandle& proc, uintptr_t address, std::string& out) {
    char buf[256] = {};
    auto rr = proc.read(address, buf, sizeof(buf) - 1);
    if (!rr || *rr < 4) return false;

    size_t printable = 0;
    size_t len = 0;
    for (; len < *rr && buf[len]; ++len) {
        unsigned char ch = static_cast<unsigned char>(buf[len]);
        if (ch >= 32 && ch < 127) ++printable;
        else return false;
    }
    if (printable < 4) return false;
    out.assign(buf, len);
    return true;
}

} // namespace

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
                ref.target = parseDirectTarget(inst.operands).value_or(0);
                if (ref.target) refs.push_back(ref);
            }
            // JMP instructions
            else if (inst.mnemonic == "jmp" || (!inst.mnemonic.empty() && inst.mnemonic[0] == 'j')) {
                CodeRef ref;
                ref.address = inst.address;
                ref.type = RefType::Jump;
                ref.text = inst.mnemonic + " " + inst.operands;
                ref.target = parseDirectTarget(inst.operands).value_or(0);
                if (ref.target) refs.push_back(ref);
            }
            // RIP-relative memory operands often reference literals in nearby rodata.
            else if (auto target = parseRipRelativeTarget(inst)) {
                CodeRef ref;
                ref.address = inst.address;
                ref.type = RefType::String;
                ref.text = inst.mnemonic + " " + inst.operands;
                ref.target = *target;
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
        if (ref.type != RefType::String || !ref.target) continue;
        std::string text;
        if (readPrintableString(proc, ref.target, text)) {
            ref.text = std::move(text);
            strings.push_back(ref);
        }
    }
    return strings;
}

std::vector<CodeRef> CodeAnalyzer::findReferencedFunctions(ProcessHandle& proc, const ModuleInfo& module) {
    auto allRefs = dissectModule(proc, module);
    std::vector<CodeRef> functions;
    for (auto& ref : allRefs) {
        if (ref.type == RefType::Call && ref.target)
            functions.push_back(ref);
    }
    return functions;
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
