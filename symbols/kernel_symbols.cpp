#include "symbols/kernel_symbols.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <sstream>

namespace ce {
namespace {

std::string stripModuleBrackets(std::string module) {
    if (module.size() >= 2 && module.front() == '[' && module.back() == ']')
        return module.substr(1, module.size() - 2);
    return module;
}

std::string moduleQualifier(const KernelSymbol& symbol) {
    return symbol.module.empty() ? "kernel" : symbol.module;
}

} // namespace

void KernelSymbolResolver::clear() {
    symbols_.clear();
    addrIndex_.clear();
    nameIndex_.clear();
}

bool KernelSymbolResolver::loadFile(const std::string& path, bool includeZeroAddresses) {
    std::ifstream input(path);
    if (!input)
        return false;
    return load(input, includeZeroAddresses);
}

bool KernelSymbolResolver::load(std::istream& input, bool includeZeroAddresses) {
    clear();

    std::string line;
    while (std::getline(input, line)) {
        std::istringstream row(line);
        std::string addressText;
        std::string typeText;
        KernelSymbol symbol;

        if (!(row >> addressText >> typeText >> symbol.name))
            continue;
        if (typeText.empty())
            continue;

        try {
            symbol.address = static_cast<uintptr_t>(std::stoull(addressText, nullptr, 16));
        } catch (...) {
            continue;
        }
        if (symbol.address == 0 && !includeZeroAddresses)
            continue;

        symbol.type = typeText.front();
        std::string module;
        if (row >> module)
            symbol.module = stripModuleBrackets(module);

        indexSymbol(std::move(symbol));
    }

    return true;
}

void KernelSymbolResolver::indexSymbol(KernelSymbol symbol) {
    auto address = symbol.address;
    auto name = symbol.name;
    auto qualified = moduleQualifier(symbol) + "!" + symbol.name;

    size_t index = symbols_.size();
    symbols_.push_back(std::move(symbol));
    addrIndex_[address] = index;
    if (!nameIndex_.contains(name))
        nameIndex_[std::move(name)] = address;
    if (!nameIndex_.contains(qualified))
        nameIndex_[std::move(qualified)] = address;
}

uintptr_t KernelSymbolResolver::lookup(const std::string& name) const {
    auto it = nameIndex_.find(name);
    return it == nameIndex_.end() ? 0 : it->second;
}

std::string KernelSymbolResolver::resolve(uintptr_t address) const {
    if (addrIndex_.empty())
        return {};

    auto it = addrIndex_.upper_bound(address);
    if (it == addrIndex_.begin())
        return {};
    --it;

    const auto& symbol = symbols_[it->second];
    auto offset = address - symbol.address;
    if (offset > 0x1000)
        return {};

    auto result = moduleQualifier(symbol) + "!" + symbol.name;
    if (offset != 0) {
        char suffix[32];
        std::snprintf(suffix, sizeof(suffix), "+0x%lx", static_cast<unsigned long>(offset));
        result += suffix;
    }
    return result;
}

} // namespace ce
