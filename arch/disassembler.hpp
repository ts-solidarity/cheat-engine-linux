#pragma once
/// Disassembler wrapping Capstone library.
/// Supports x86-32, x86-64, ARM32, ARM64.

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <span>

namespace ce {

struct Instruction {
    uintptr_t    address;
    std::vector<uint8_t> bytes;
    std::string  mnemonic;
    std::string  operands;
    uint8_t      size;

    std::string toString() const;
};

enum class Arch { X86_32, X86_64, ARM32, ARM64 };

class Disassembler {
public:
    explicit Disassembler(Arch arch = Arch::X86_64);
    ~Disassembler();

    Disassembler(const Disassembler&) = delete;
    Disassembler& operator=(const Disassembler&) = delete;

    /// Disassemble `count` instructions starting at `address` from `code`.
    /// If count == 0, disassembles as many as possible.
    std::vector<Instruction> disassemble(uintptr_t address, std::span<const uint8_t> code, size_t count = 0);

    /// Disassemble a single instruction. Returns nullopt if invalid.
    std::optional<Instruction> disassembleOne(uintptr_t address, std::span<const uint8_t> code);

    Arch arch() const { return arch_; }

private:
    Arch arch_;
    size_t handle_ = 0; // csh handle
};

} // namespace ce
