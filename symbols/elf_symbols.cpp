#include "symbols/elf_symbols.hpp"

#include <fstream>
#include <cstring>
#include <elf.h>
#include <filesystem>
#include <algorithm>

namespace ce {

void SymbolResolver::clear() {
    symbols_.clear();
    addrIndex_.clear();
    nameIndex_.clear();
}

void SymbolResolver::loadProcess(ProcessHandle& proc) {
    clear();
    auto modules = proc.modules();
    for (auto& m : modules) {
        if (m.path.empty() || m.path[0] != '/') continue;
        if (!std::filesystem::exists(m.path)) continue;
        parseElfSymbols(m.path, m.name, m.base);
    }
}

void SymbolResolver::loadModule(const std::string& path, const std::string& moduleName, uintptr_t baseAddr) {
    parseElfSymbols(path, moduleName, baseAddr);
}

void SymbolResolver::parseElfSymbols(const std::string& path, const std::string& moduleName, uintptr_t baseAddr) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return;

    // Read ELF header
    Elf64_Ehdr ehdr;
    f.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
    if (!f) return;

    // Verify ELF magic
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return;

    // Only support 64-bit for now
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) return;

    // Read section headers
    if (ehdr.e_shoff == 0 || ehdr.e_shnum == 0) return;

    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    f.seekg(ehdr.e_shoff);
    f.read(reinterpret_cast<char*>(shdrs.data()), ehdr.e_shnum * sizeof(Elf64_Shdr));
    if (!f) return;

    // Determine if this is a position-independent executable (PIE/shared lib)
    // If ET_DYN, symbol addresses are relative to base and we need to add baseAddr
    // If ET_EXEC, symbol addresses are absolute
    bool isPIE = (ehdr.e_type == ET_DYN);

    // Find symbol tables (.dynsym and .symtab) and their string tables
    auto processSymtab = [&](const Elf64_Shdr& symShdr, const Elf64_Shdr& strShdr) {
        if (symShdr.sh_entsize == 0) return;

        // Read string table
        std::vector<char> strtab(strShdr.sh_size);
        f.seekg(strShdr.sh_offset);
        f.read(strtab.data(), strShdr.sh_size);
        if (!f) return;

        // Read symbol entries
        size_t numSyms = symShdr.sh_size / symShdr.sh_entsize;
        std::vector<Elf64_Sym> syms(numSyms);
        f.seekg(symShdr.sh_offset);
        f.read(reinterpret_cast<char*>(syms.data()), symShdr.sh_size);
        if (!f) return;

        for (auto& sym : syms) {
            // Skip undefined, no-name, and non-function/object symbols
            if (sym.st_name == 0) continue;
            if (sym.st_shndx == SHN_UNDEF) continue;
            if (sym.st_name >= strShdr.sh_size) continue;

            uint8_t type = ELF64_ST_TYPE(sym.st_info);
            if (type != STT_FUNC && type != STT_OBJECT && type != STT_NOTYPE) continue;

            const char* name = strtab.data() + sym.st_name;
            if (name[0] == '\0') continue;

            uintptr_t addr = sym.st_value;
            if (isPIE) addr += baseAddr;

            Symbol s;
            s.name = name;
            s.address = addr;
            s.size = sym.st_size;
            s.module = moduleName;

            size_t idx = symbols_.size();
            symbols_.push_back(std::move(s));
            addrIndex_[addr] = idx;
            if (!nameIndex_.count(name))
                nameIndex_[std::string(name)] = addr;
        }
    };

    for (size_t i = 0; i < shdrs.size(); ++i) {
        if ((shdrs[i].sh_type == SHT_DYNSYM || shdrs[i].sh_type == SHT_SYMTAB) &&
            shdrs[i].sh_link < shdrs.size()) {
            processSymtab(shdrs[i], shdrs[shdrs[i].sh_link]);
        }
    }
}

std::string SymbolResolver::resolve(uintptr_t address) const {
    if (addrIndex_.empty()) return {};

    // Find the symbol at or before this address
    auto it = addrIndex_.upper_bound(address);
    if (it == addrIndex_.begin()) return {};
    --it;

    auto& sym = symbols_[it->second];

    // Check if address is within the symbol's range (or within a reasonable distance)
    uintptr_t offset = address - sym.address;
    if (sym.size > 0 && offset >= sym.size) {
        // Address is past this symbol. Only show if within 4KB (likely still in the function)
        if (offset > 0x1000) return {};
    }

    if (offset == 0)
        return sym.module + "!" + sym.name;
    else {
        char buf[32];
        snprintf(buf, sizeof(buf), "+0x%lx", offset);
        return sym.module + "!" + sym.name + buf;
    }
}

uintptr_t SymbolResolver::lookup(const std::string& name) const {
    auto it = nameIndex_.find(name);
    return it != nameIndex_.end() ? it->second : 0;
}

} // namespace ce
