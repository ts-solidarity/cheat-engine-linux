#include "arch/disassembler.hpp"
#include <capstone/capstone.h>
#include <stdexcept>
#include <format>

namespace ce {

std::string Instruction::toString() const {
    std::string hex;
    for (auto b : bytes)
        hex += std::format("{:02x} ", b);
    return std::format("{:016x}  {:<24s} {} {}", address, hex, mnemonic, operands);
}

Disassembler::Disassembler(Arch arch) : arch_(arch) {
    cs_arch cs_a;
    cs_mode cs_m;

    switch (arch) {
        case Arch::X86_32: cs_a = CS_ARCH_X86; cs_m = CS_MODE_32; break;
        case Arch::X86_64: cs_a = CS_ARCH_X86; cs_m = CS_MODE_64; break;
        case Arch::ARM32:  cs_a = CS_ARCH_ARM; cs_m = CS_MODE_ARM; break;
        case Arch::ARM64:  cs_a = CS_ARCH_ARM64; cs_m = CS_MODE_ARM; break;
    }

    csh h;
    if (cs_open(cs_a, cs_m, &h) != CS_ERR_OK)
        throw std::runtime_error("Failed to initialize Capstone");

    cs_option(h, CS_OPT_DETAIL, CS_OPT_OFF); // We don't need detailed operand info yet
    handle_ = h;
}

Disassembler::~Disassembler() {
    if (handle_)
        cs_close(reinterpret_cast<csh*>(&handle_));
}

std::vector<Instruction> Disassembler::disassemble(uintptr_t address, std::span<const uint8_t> code, size_t count) {
    std::vector<Instruction> result;
    cs_insn* insn = nullptr;

    size_t n = cs_disasm(static_cast<csh>(handle_), code.data(), code.size(), address, count, &insn);
    if (n == 0) return result;

    result.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        Instruction inst;
        inst.address = insn[i].address;
        inst.size = insn[i].size;
        inst.mnemonic = insn[i].mnemonic;
        inst.operands = insn[i].op_str;
        inst.bytes.assign(insn[i].bytes, insn[i].bytes + insn[i].size);
        result.push_back(std::move(inst));
    }

    cs_free(insn, n);
    return result;
}

std::optional<Instruction> Disassembler::disassembleOne(uintptr_t address, std::span<const uint8_t> code) {
    auto result = disassemble(address, code, 1);
    if (result.empty()) return std::nullopt;
    return std::move(result[0]);
}

} // namespace ce
