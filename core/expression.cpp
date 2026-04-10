#include "core/expression.hpp"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace ce {

static std::string trim(const std::string& s) {
    auto a = s.find_first_not_of(" \t");
    auto b = s.find_last_not_of(" \t");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

uintptr_t ExpressionParser::resolveToken(const std::string& token) const {
    if (token.empty()) return 0;

    // Hex with prefix
    if (token.size() > 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X'))
        return std::stoull(token.substr(2), nullptr, 16);

    // Decimal with # prefix
    if (token[0] == '#')
        return std::stoull(token.substr(1), nullptr, 10);

    // Try as plain hex
    bool allHex = std::all_of(token.begin(), token.end(),
        [](char c) { return std::isxdigit(c); });
    if (allHex && token.size() >= 2)
        return std::stoull(token, nullptr, 16);

    // Try symbol resolver
    if (resolver_) {
        auto addr = resolver_->lookup(token);
        if (addr) return addr;
    }

    // Try module name → base address
    if (proc_) {
        auto mods = proc_->modules();
        for (auto& m : mods)
            if (m.name == token) return m.base;
    }

    return 0;
}

std::optional<uintptr_t> ExpressionParser::parse(const std::string& expr) const {
    auto s = trim(expr);
    if (s.empty()) return std::nullopt;

    // Handle pointer dereference: [expr]+offset
    if (s[0] == '[') {
        auto closeB = s.find(']');
        if (closeB == std::string::npos) return std::nullopt;

        auto inner = s.substr(1, closeB - 1);
        auto innerVal = parse(inner);
        if (!innerVal || !proc_) return std::nullopt;

        // Dereference
        uintptr_t ptr = 0;
        auto r = proc_->read(*innerVal, &ptr, sizeof(ptr));
        if (!r || *r < sizeof(ptr)) return std::nullopt;

        // Apply remaining offset after ']'
        auto rest = trim(s.substr(closeB + 1));
        if (rest.empty()) return ptr;

        // Parse +/- offset
        if (rest[0] == '+') {
            auto offsetVal = parse(rest.substr(1));
            return offsetVal ? std::optional(ptr + *offsetVal) : std::nullopt;
        } else if (rest[0] == '-') {
            auto offsetVal = parse(rest.substr(1));
            return offsetVal ? std::optional(ptr - *offsetVal) : std::nullopt;
        }
        return ptr;
    }

    // Split by + and - for arithmetic
    uintptr_t result = 0;
    bool first = true;
    bool subtract = false;
    size_t pos = 0;

    while (pos < s.size()) {
        // Find next + or - (not inside 0x prefix)
        size_t nextOp = std::string::npos;
        for (size_t i = (first ? 0 : 0); i < s.size(); ++i) {
            if (i > pos && (s[i] == '+' || s[i] == '-') &&
                !(i > 1 && (s[i-1] == 'x' || s[i-1] == 'X'))) {
                nextOp = i;
                break;
            }
        }

        std::string token;
        if (nextOp == std::string::npos) {
            token = trim(s.substr(pos));
            pos = s.size();
        } else {
            token = trim(s.substr(pos, nextOp - pos));
            pos = nextOp;
        }

        if (!token.empty()) {
            auto val = resolveToken(token);
            if (subtract)
                result -= val;
            else
                result += val;
        }

        if (pos < s.size()) {
            subtract = (s[pos] == '-');
            ++pos;
        }
        first = false;
    }

    return result;
}

} // namespace ce
