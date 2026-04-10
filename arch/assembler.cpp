#include "arch/assembler.hpp"
#include <keystone/keystone.h>
#include <stdexcept>

namespace ce {

Assembler::Assembler(AsmArch arch) : arch_(arch) {
    ks_arch ka;
    ks_mode km;
    switch (arch) {
        case AsmArch::X86_32: ka = KS_ARCH_X86; km = KS_MODE_32; break;
        case AsmArch::X86_64: ka = KS_ARCH_X86; km = KS_MODE_64; break;
    }

    ks_engine* ks;
    if (ks_open(ka, km, &ks) != KS_ERR_OK)
        throw std::runtime_error("Failed to initialize Keystone");

    // Use NASM syntax (matches CE's assembler style)
    ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
    handle_ = reinterpret_cast<size_t>(ks);
}

Assembler::~Assembler() {
    if (handle_)
        ks_close(reinterpret_cast<ks_engine*>(handle_));
}

std::expected<std::vector<uint8_t>, std::string>
Assembler::assemble(const std::string& code, uintptr_t address) {
    size_t stmts;
    return assembleEx(code, address, stmts);
}

std::expected<std::vector<uint8_t>, std::string>
Assembler::assembleEx(const std::string& code, uintptr_t address, size_t& statementsOut) {
    auto* ks = reinterpret_cast<ks_engine*>(handle_);
    unsigned char* encoded = nullptr;
    size_t size = 0;
    size_t count = 0;

    int r = ks_asm(ks, code.c_str(), address, &encoded, &size, &count);
    if (r != 0) {
        auto err = ks_errno(ks);
        return std::unexpected(std::string("Assembly error: ") + ks_strerror(err));
    }

    std::vector<uint8_t> result(encoded, encoded + size);
    statementsOut = count;
    ks_free(encoded);
    return result;
}

} // namespace ce
