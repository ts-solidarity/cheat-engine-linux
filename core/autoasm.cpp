#include "core/autoasm.hpp"
#include "arch/disassembler.hpp"
#include "platform/linux/injector.hpp"
#include "symbols/elf_symbols.hpp"
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <regex>
#include <string_view>
#include <utility>
#include <vector>

namespace ce {

// ── Helpers ──

static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    auto end = s.find_last_not_of(" \t\r\n");
    return (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
}

static std::string toUpper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    return s;
}

static std::string normalizeCommandName(const std::string& name) {
    return toUpper(trim(name));
}

static bool startsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static std::string stripOptionalQuotes(std::string s) {
    s = trim(s);
    if (s.size() >= 2 &&
        ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\''))) {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

static std::vector<std::string> splitArgs(const std::string& args, size_t maxParts) {
    std::vector<std::string> parts;
    std::string current;
    char quote = 0;

    for (char c : args) {
        if ((c == '"' || c == '\'') && (quote == 0 || quote == c)) {
            quote = quote == c ? 0 : c;
            current.push_back(c);
            continue;
        }
        if (c == ',' && quote == 0 && parts.size() + 1 < maxParts) {
            parts.push_back(trim(current));
            current.clear();
            continue;
        }
        current.push_back(c);
    }

    parts.push_back(trim(current));
    return parts;
}

static std::string formatHex(uintptr_t address) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%lx", address);
    return buf;
}

static std::string formatHexLiteral(uintptr_t address) {
    return "0x" + formatHex(address);
}

static std::string stripInlineComment(std::string line) {
    auto commentPos = line.find("//");
    if (commentPos != std::string::npos)
        line = line.substr(0, commentPos);
    return trim(line);
}

static bool runScriptHooks(const std::vector<AutoAssembler::ScriptHook>& hooks,
    std::string& code, std::vector<std::string>& log, std::string& error, const char* phase) {
    for (size_t i = 0; i < hooks.size(); ++i) {
        if (!hooks[i](code, log, error)) {
            if (error.empty())
                error = std::string("Auto-assembler ") + phase + " hook failed at index " + std::to_string(i);
            return false;
        }
    }
    return true;
}

static bool parseWholeUnsigned(const std::string& text, int base, uint64_t& value) {
    auto s = trim(text);
    if (s.empty())
        return false;

    size_t parsed = 0;
    try {
        value = std::stoull(s, &parsed, base);
    } catch (...) {
        return false;
    }
    return parsed == s.size();
}

static bool moduleMatches(const ModuleInfo& module, const std::string& requested) {
    auto req = stripOptionalQuotes(requested);
    auto reqUpper = toUpper(req);
    return toUpper(module.name) == reqUpper || toUpper(module.path) == reqUpper;
}

static size_t findAobInRange(ProcessHandle& proc, uintptr_t start, uintptr_t stop,
                             const std::vector<uint8_t>& pattern,
                             const std::vector<bool>& mask,
                             uintptr_t& firstMatch) {
    if (pattern.empty() || stop <= start)
        return 0;

    size_t matches = 0;
    auto regions = proc.queryRegions();
    for (const auto& region : regions) {
        if (region.state != MemState::Committed || !(region.protection & MemProt::Read))
            continue;

        uintptr_t regionStart = std::max(region.base, start);
        uintptr_t regionEnd = std::min(region.base + region.size, stop);
        if (regionEnd <= regionStart || regionEnd - regionStart < pattern.size())
            continue;

        std::vector<uint8_t> buffer(regionEnd - regionStart);
        auto readResult = proc.read(regionStart, buffer.data(), buffer.size());
        if (!readResult || *readResult < pattern.size())
            continue;

        size_t bytesRead = *readResult;
        size_t limit = bytesRead - pattern.size() + 1;
        for (size_t offset = 0; offset < limit; ++offset) {
            bool matched = true;
            for (size_t i = 0; i < pattern.size(); ++i) {
                if (i < mask.size() && !mask[i])
                    continue;
                if (buffer[offset + i] != pattern[i]) {
                    matched = false;
                    break;
                }
            }
            if (matched) {
                if (matches == 0)
                    firstMatch = regionStart + offset;
                ++matches;
            }
        }
    }

    return matches;
}

static std::vector<std::string> splitDataValues(const std::string& data) {
    std::vector<std::string> values;
    std::string current;
    char quote = 0;

    for (char c : data) {
        if ((c == '"' || c == '\'') && (quote == 0 || quote == c)) {
            quote = quote == c ? 0 : c;
            current.push_back(c);
            continue;
        }
        if (quote == 0 && (c == ',' || std::isspace(static_cast<unsigned char>(c)))) {
            if (!trim(current).empty()) {
                values.push_back(trim(current));
                current.clear();
            }
            continue;
        }
        current.push_back(c);
    }

    if (!trim(current).empty())
        values.push_back(trim(current));
    return values;
}

static bool parseDataDirective(const std::string& op, const std::string& data,
                               std::vector<uint8_t>& bytes, std::string& error) {
    size_t width = 1;
    if (op == "DW") width = 2;
    else if (op == "DD") width = 4;
    else if (op == "DQ") width = 8;

    auto values = splitDataValues(data);
    if (values.empty()) {
        error = op + " requires at least one value";
        return false;
    }

    uint64_t maxValue = width == 8 ? UINT64_MAX : ((uint64_t{1} << (width * 8)) - 1);
    for (auto token : values) {
        token = trim(token);
        if (token.size() >= 2 &&
            ((token.front() == '"' && token.back() == '"') || (token.front() == '\'' && token.back() == '\''))) {
            if (width != 1) {
                error = op + " string literal is only supported for DB";
                return false;
            }
            auto text = stripOptionalQuotes(token);
            bytes.insert(bytes.end(), text.begin(), text.end());
            continue;
        }

        uint64_t value = 0;
        try {
            value = std::stoull(token, nullptr, 16);
        } catch (...) {
            error = "Invalid " + op + " value: " + token;
            return false;
        }

        if (value > maxValue) {
            error = op + " value out of range: " + token;
            return false;
        }

        for (size_t i = 0; i < width; ++i)
            bytes.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }

    return true;
}

static bool parseStructDataSize(const std::string& line, size_t& size, std::string& error) {
    auto trimmed = trim(line);
    auto upper = toUpper(trimmed);
    size = 0;

    if (startsWith(upper, "DB ") || startsWith(upper, "DW ") ||
        startsWith(upper, "DD ") || startsWith(upper, "DQ ")) {
        size_t width = 1;
        auto op = upper.substr(0, 2);
        if (op == "DW") width = 2;
        else if (op == "DD") width = 4;
        else if (op == "DQ") width = 8;

        auto values = splitDataValues(trimmed.substr(3));
        if (values.empty()) {
            error = "STRUCT data directive requires at least one value";
            return false;
        }

        for (auto token : values) {
            token = trim(token);
            if (token.size() >= 2 &&
                ((token.front() == '"' && token.back() == '"') || (token.front() == '\'' && token.back() == '\''))) {
                if (width != 1) {
                    error = "STRUCT string literal is only supported for DB";
                    return false;
                }
                size += stripOptionalQuotes(token).size();
                continue;
            }
            size += width;
        }
        return true;
    }

    if (startsWith(upper, "DS ")) {
        auto text = stripOptionalQuotes(trimmed.substr(3));
        if (text.empty()) {
            error = "STRUCT DS requires a string";
            return false;
        }
        size = text.size();
        return true;
    }

    return false;
}

static bool isSimpleLabelDefinition(const std::string& line) {
    return !line.empty() && line.back() == ':' && line.find_first_of(" \t") == std::string::npos;
}

static bool parseNopCount(const std::string& countExpr, size_t& count, std::string& error) {
    try {
        count = countExpr.empty() ? 1 : std::stoull(countExpr, nullptr, 0);
    } catch (...) {
        error = "Invalid NOP count: " + countExpr;
        return false;
    }
    if (count == 0) {
        error = "NOP count must be greater than zero";
        return false;
    }
    return true;
}

static bool expandStructDefinitions(const std::string& code, std::string& expanded,
                                    std::vector<std::string>& log, std::string& error) {
    std::istringstream ss(code);
    std::string rawLine;
    std::string generated;
    std::string body;
    bool inStruct = false;
    std::string structName;
    size_t offset = 0;

    while (std::getline(ss, rawLine)) {
        auto line = stripInlineComment(rawLine);
        auto upper = toUpper(line);

        if (!inStruct) {
            if (startsWith(upper, "STRUCT ")) {
                structName = trim(line.substr(7));
                if (structName.empty()) {
                    error = "STRUCT requires a name";
                    return false;
                }
                inStruct = true;
                offset = 0;
                log.push_back("STRUCT: " + structName);
                continue;
            }

            body += rawLine + "\n";
            continue;
        }

        if (line.empty() || line[0] == ';' || line[0] == '/')
            continue;

        if (upper == "ENDS" || upper == "ENDSTRUCT") {
            generated += "define(" + structName + "," + formatHexLiteral(offset) + ")\n";
            log.push_back("ENDSTRUCT: " + structName + " size=" + std::to_string(offset));
            inStruct = false;
            structName.clear();
            continue;
        }

        auto work = line;
        auto colon = work.find(':');
        if (colon != std::string::npos) {
            auto field = trim(work.substr(0, colon));
            if (field.empty()) {
                error = "STRUCT has an empty field name";
                return false;
            }

            auto value = formatHexLiteral(offset);
            generated += "define(" + structName + "." + field + "," + value + ")\n";
            generated += "define(" + field + "," + value + ")\n";
            log.push_back("STRUCT: " + structName + "." + field + " = " + value);
            work = trim(work.substr(colon + 1));
            if (work.empty())
                continue;
            upper = toUpper(work);
        }

        size_t dataSize = 0;
        std::string sizeError;
        if (parseStructDataSize(work, dataSize, sizeError)) {
            offset += dataSize;
            continue;
        }
        if (!sizeError.empty()) {
            error = sizeError;
            return false;
        }

        error = "Unsupported STRUCT line in " + structName + ": " + work;
        return false;
    }

    if (inStruct) {
        error = "STRUCT missing ENDSTRUCT/ENDS: " + structName;
        return false;
    }

    expanded = generated + body;
    return true;
}

// Parse "name, size [, preferred]" from inside ALLOC(...)
static bool parseAllocArgs(const std::string& args, std::string& name, size_t& size, uintptr_t& preferred) {
    std::istringstream ss(args);
    std::string token;
    std::getline(ss, token, ','); name = trim(token);
    if (!std::getline(ss, token, ',')) return false;
    size = std::stoull(trim(token), nullptr, 0);
    preferred = 0;
    if (std::getline(ss, token, ','))
        preferred = std::stoull(trim(token), nullptr, 16);
    return true;
}

// ── Section extraction ──

std::string AutoAssembler::extractSection(const std::string& script, const std::string& section) {
    auto tag = "[" + section + "]";
    auto tagUpper = toUpper(tag);
    std::istringstream ss(script);
    std::string line;
    std::string result;
    bool inSection = false;

    while (std::getline(ss, line)) {
        auto trimmed = toUpper(trim(line));
        if (trimmed == tagUpper) {
            inSection = true;
            continue;
        }
        if (inSection && trimmed.size() > 2 && trimmed[0] == '[' && trimmed.back() == ']') {
            break; // Next section
        }
        if (inSection)
            result += line + "\n";
    }
    return result;
}

// ── Line parsing ──

bool AutoAssembler::parseLine(const std::string& rawLine,
    std::vector<Alloc>& allocs, std::vector<Label>& labels,
    std::vector<Define>& defines, std::vector<std::string>& registeredSymbols,
    std::vector<std::string>& asmLines, std::vector<std::string>& log,
    ProcessHandle* proc, std::string& error)
{
    auto line = trim(rawLine);
    if (line.empty() || line[0] == '/' || line[0] == ';') return true; // Comment

    // Strip inline comments
    auto commentPos = line.find("//");
    if (commentPos != std::string::npos) line = trim(line.substr(0, commentPos));
    if (line.empty()) return true;

    auto upper = toUpper(line);

    // ALLOC(name, size [, preferred])
    if (startsWith(upper, "ALLOC(") && line.back() == ')') {
        auto args = line.substr(6, line.size() - 7);
        Alloc a;
        parseAllocArgs(args, a.name, a.size, a.preferred);
        a.address = 0;
        allocs.push_back(a);
        log.push_back("ALLOC: " + a.name + " size=" + std::to_string(a.size));
        return true;
    }

    if (startsWith(upper, "DEALLOC(") && line.back() == ')') {
        auto args = line.substr(8, line.size() - 9);
        asmLines.push_back("__DEALLOC__:" + args);
        return true;
    }

    // LABEL(name1, name2, ...)
    if (startsWith(upper, "LABEL(") && line.back() == ')') {
        auto args = line.substr(6, line.size() - 7);
        std::istringstream ss(args);
        std::string name;
        while (std::getline(ss, name, ',')) {
            Label l;
            l.name = trim(name);
            l.address = 0;
            labels.push_back(l);
        }
        return true;
    }

    // DEFINE(name, value)
    if (startsWith(upper, "DEFINE(") && line.back() == ')') {
        auto args = line.substr(7, line.size() - 8);
        auto comma = args.find(',');
        if (comma != std::string::npos) {
            Define d;
            d.name = trim(args.substr(0, comma));
            d.value = trim(args.substr(comma + 1));
            defines.push_back(d);
        }
        return true;
    }

    // REGISTERSYMBOL(name)
    if (startsWith(upper, "REGISTERSYMBOL(") && line.back() == ')') {
        auto args = line.substr(15, line.size() - 16);
        std::istringstream ss(args);
        std::string name;
        while (std::getline(ss, name, ','))
            registeredSymbols.push_back(trim(name));
        return true;
    }

    if (startsWith(upper, "UNREGISTERSYMBOL(") && line.back() == ')') {
        constexpr std::string_view prefix = "UNREGISTERSYMBOL(";
        auto args = line.substr(prefix.size(), line.size() - prefix.size() - 1);
        asmLines.push_back("__UNREGISTERSYMBOL__:" + args);
        return true;
    }

    // FULLACCESS(address, size) — make memory writable
    if (startsWith(upper, "FULLACCESS(") && line.back() == ')') {
        auto args = line.substr(11, line.size() - 12);
        asmLines.push_back("__FULLACCESS__:" + args);
        return true;
    }

    // ASSERT(address, bytes) — verify bytes at address before proceeding
    if (startsWith(upper, "ASSERT(") && line.back() == ')') {
        auto args = line.substr(7, line.size() - 8);
        auto comma = args.find(',');
        if (comma != std::string::npos) {
            auto addrExpr = trim(args.substr(0, comma));
            auto bytesStr = trim(args.substr(comma + 1));
            log.push_back("ASSERT: " + addrExpr + " = " + bytesStr);
        }
        asmLines.push_back("__ASSERT__:" + args);
        return true;
    }

    // AOBSCANREGION(name, start, stop, pattern) — find pattern in an address range
    if (startsWith(upper, "AOBSCANREGION(") && line.back() == ')' && proc) {
        auto args = line.substr(14, line.size() - 15);
        auto parts = splitArgs(args, 4);
        if (parts.size() == 4) {
            auto name = trim(parts[0]);
            auto startExpr = trim(parts[1]);
            auto stopExpr = trim(parts[2]);
            auto pattern = stripOptionalQuotes(parts[3]);
            auto start = resolveAddress(startExpr, allocs, labels, defines);
            auto stop = resolveAddress(stopExpr, allocs, labels, defines);
            if (!start || !stop || stop <= start) {
                log.push_back("AOBSCANREGION: " + name + " invalid range");
                return true;
            }

            ScanConfig cfg;
            cfg.parseAOB(pattern);
            uintptr_t addr = 0;
            size_t matches = findAobInRange(*proc, start, stop, cfg.byteArray, cfg.byteArrayMask, addr);
            if (matches > 0) {
                Define d;
                d.name = name;
                d.value = formatHex(addr);
                defines.push_back(d);
                log.push_back("AOBSCANREGION: " + name + " = 0x" + d.value +
                    " (" + std::to_string(matches) + " matches)");
            } else {
                log.push_back("AOBSCANREGION: " + name + " NOT FOUND");
            }
        }
        return true;
    }

    // AOBSCANALL(name, pattern) — find pattern across all readable memory
    if (startsWith(upper, "AOBSCANALL(") && line.back() == ')' && proc) {
        auto args = line.substr(11, line.size() - 12);
        auto parts = splitArgs(args, 2);
        if (parts.size() == 2) {
            auto name = trim(parts[0]);
            auto pattern = stripOptionalQuotes(parts[1]);

            ScanConfig cfg;
            cfg.valueType = ValueType::ByteArray;
            cfg.parseAOB(pattern);
            cfg.alignment = 1;

            MemoryScanner scanner;
            auto result = scanner.firstScan(*proc, cfg);
            if (result.count() > 0) {
                Define d;
                d.name = name;
                d.value = formatHex(result.address(0));
                defines.push_back(d);
                log.push_back("AOBSCANALL: " + name + " = 0x" + d.value +
                    " (" + std::to_string(result.count()) + " matches)");
            } else {
                log.push_back("AOBSCANALL: " + name + " NOT FOUND");
            }
        }
        return true;
    }

    // AOBSCANMODULE(name, module, pattern) — find pattern inside one module
    if (startsWith(upper, "AOBSCANMODULE(") && line.back() == ')' && proc) {
        auto args = line.substr(14, line.size() - 15);
        auto parts = splitArgs(args, 3);
        if (parts.size() == 3) {
            auto name = trim(parts[0]);
            auto moduleName = stripOptionalQuotes(parts[1]);
            auto pattern = stripOptionalQuotes(parts[2]);

            auto modules = proc->modules();
            auto moduleIt = std::find_if(modules.begin(), modules.end(), [&](const ModuleInfo& module) {
                return moduleMatches(module, moduleName);
            });
            if (moduleIt == modules.end()) {
                log.push_back("AOBSCANMODULE: " + name + " module not found: " + moduleName);
                return true;
            }

            ScanConfig cfg;
            cfg.parseAOB(pattern);
            uintptr_t addr = 0;
            size_t matches = findAobInRange(*proc, moduleIt->base, moduleIt->base + moduleIt->size,
                cfg.byteArray, cfg.byteArrayMask, addr);
            if (matches > 0) {
                Define d;
                d.name = name;
                d.value = formatHex(addr);
                defines.push_back(d);
                log.push_back("AOBSCANMODULE: " + name + " = 0x" + d.value +
                    " in " + moduleIt->name + " (" + std::to_string(matches) + " matches)");
            } else {
                log.push_back("AOBSCANMODULE: " + name + " NOT FOUND in " + moduleIt->name);
            }
        }
        return true;
    }

    // AOBSCAN(name, pattern) — find pattern
    if (startsWith(upper, "AOBSCAN(") && line.back() == ')' && proc) {
        auto args = line.substr(8, line.size() - 9);
        auto parts = splitArgs(args, 2);
        if (parts.size() == 2) {
            auto name = trim(parts[0]);
            auto pattern = stripOptionalQuotes(parts[1]);

            // Use our scanner's AOB
            ScanConfig cfg;
            cfg.valueType = ValueType::ByteArray;
            cfg.parseAOB(pattern);
            cfg.alignment = 1;

            MemoryScanner scanner;
            auto result = scanner.firstScan(*proc, cfg);
            if (result.count() > 0) {
                uintptr_t addr = result.address(0);
                Define d;
                d.name = name;
                d.value = formatHex(addr);
                defines.push_back(d);
                log.push_back("AOBSCAN: " + name + " = 0x" + d.value +
                    " (" + std::to_string(result.count()) + " matches)");
            } else {
                log.push_back("AOBSCAN: " + name + " NOT FOUND");
            }
        }
        return true;
    }

    // CREATETHREAD(address) — create remote thread at address after injection
    if (startsWith(upper, "CREATETHREAD(") && line.back() == ')') {
        auto addr = trim(line.substr(13, line.size() - 14));
        log.push_back("CREATETHREAD: " + addr + " (deferred to post-injection)");
        // Store for execution after all writes complete
        asmLines.push_back("__CREATETHREAD__:" + addr);
        return true;
    }

    // CREATETHREADANDWAIT(address[, timeout])
    if (startsWith(upper, "CREATETHREADANDWAIT(") && line.back() == ')') {
        auto args = trim(line.substr(20, line.size() - 21));
        log.push_back("CREATETHREADANDWAIT: " + args);
        asmLines.push_back("__CREATETHREADANDWAIT__:" + args);
        return true;
    }

    // INCLUDE(filename) — include another .cea script
    if (startsWith(upper, "INCLUDE(") && line.back() == ')') {
        auto filename = trim(line.substr(8, line.size() - 9));
        // Remove quotes
        if (!filename.empty() && filename.front() == '"') filename = filename.substr(1);
        if (!filename.empty() && filename.back() == '"') filename.pop_back();
        // Read the file and parse each line
        std::ifstream incFile(filename);
        if (incFile) {
            std::string incLine;
            while (std::getline(incFile, incLine)) {
                if (!parseLine(incLine, allocs, labels, defines, registeredSymbols, asmLines, log, proc, error))
                    return false;
            }
            log.push_back("INCLUDE: " + filename + " (loaded)");
        } else {
            log.push_back("INCLUDE: " + filename + " (NOT FOUND)");
        }
        return true;
    }

    // REASSEMBLE(address) — disassemble instruction at address and re-emit it
    if (startsWith(upper, "REASSEMBLE(") && line.back() == ')' && proc) {
        auto addrExpr = trim(line.substr(11, line.size() - 12));
        asmLines.push_back("__REASSEMBLE__:" + addrExpr);
        return true;
    }

    // READMEM(address, size) — read bytes from process memory, emit as db
    if (startsWith(upper, "READMEM(") && line.back() == ')') {
        auto args = trim(line.substr(8, line.size() - 9));
        asmLines.push_back("__READMEM__:" + args);
        return true;
    }

    // LOADBINARY(address, filename)
    if (startsWith(upper, "LOADBINARY(") && line.back() == ')') {
        auto args = trim(line.substr(11, line.size() - 12));
        asmLines.push_back("__LOADBINARY__:" + args);
        return true;
    }

    // LOADLIBRARY(path) — dlopen a shared object inside the target process.
    if (startsWith(upper, "LOADLIBRARY(") && line.back() == ')') {
        auto args = trim(line.substr(12, line.size() - 13));
        asmLines.push_back("__LOADLIBRARY__:" + args);
        return true;
    }

    // FILLMEM(address, size, value)
    if (startsWith(upper, "FILLMEM(") && line.back() == ')') {
        auto args = trim(line.substr(8, line.size() - 9));
        asmLines.push_back("__FILLMEM__:" + args);
        return true;
    }

    // NOP [count] — emit one or more 0x90 bytes at the active address.
    if (upper == "NOP" || startsWith(upper, "NOP ")) {
        auto count = trim(line.size() > 3 ? line.substr(3) : "1");
        asmLines.push_back("__NOP__:" + count);
        return true;
    }

    // DS "text" — emit string bytes at the active address.
    if (startsWith(upper, "DS ")) {
        asmLines.push_back("__DS__:" + trim(line.substr(3)));
        return true;
    }

    std::string customName;
    std::string customArgs;
    auto openParen = line.find('(');
    if (openParen != std::string::npos && line.back() == ')') {
        customName = trim(line.substr(0, openParen));
        customArgs = line.substr(openParen + 1, line.size() - openParen - 2);
    } else {
        auto firstSpace = line.find_first_of(" \t");
        customName = firstSpace == std::string::npos ? line : trim(line.substr(0, firstSpace));
        customArgs = firstSpace == std::string::npos ? "" : trim(line.substr(firstSpace + 1));
    }

    auto customIt = customCommands_.find(normalizeCommandName(customName));
    if (customIt != customCommands_.end()) {
        std::vector<std::string> expandedLines;
        if (!customIt->second(customArgs, expandedLines, log, error)) {
            if (error.empty())
                error = "Custom command failed: " + customName;
            return false;
        }

        for (const auto& expandedLine : expandedLines) {
            if (!parseLine(expandedLine, allocs, labels, defines, registeredSymbols, asmLines, log, proc, error))
                return false;
        }
        return true;
    }

    // Everything else is an assembly line or label definition
    asmLines.push_back(line);
    return true;
}

// ── Symbol resolution ──

uintptr_t AutoAssembler::resolveAddress(const std::string& expr,
    const std::vector<Alloc>& allocs, const std::vector<Label>& labels,
    const std::vector<Define>& defines) const
{
    auto name = trim(expr);

    // Check allocs
    for (auto& a : allocs)
        if (a.name == name) return a.address;

    // Check labels
    for (auto& l : labels)
        if (l.name == name) return l.address;

    // Check defines
    for (auto& d : defines)
        if (d.name == name) {
            uint64_t parsed = 0;
            if (parseWholeUnsigned(d.value, 16, parsed))
                return static_cast<uintptr_t>(parsed);
        }

    // Check global symbols
    auto it = globalSymbols_.find(name);
    if (it != globalSymbols_.end()) return it->second;

    // Try module+offset format (module.exe+1234)
    auto plus = name.find('+');
    if (plus != std::string::npos) {
        auto base = name.substr(0, plus);
        auto offset = name.substr(plus + 1);
        auto baseAddr = resolveAddress(base, allocs, labels, defines);
        if (baseAddr) {
            uint64_t parsedOffset = 0;
            if (parseWholeUnsigned(offset, 16, parsedOffset))
                return baseAddr + static_cast<uintptr_t>(parsedOffset);
        }
    }

    // Try as hex address
    uint64_t parsed = 0;
    if (parseWholeUnsigned(name, 16, parsed))
        return static_cast<uintptr_t>(parsed);

    return 0;
}

std::string AutoAssembler::substituteSymbols(const std::string& line,
    const std::vector<Alloc>& allocs, const std::vector<Label>& labels,
    const std::vector<Define>& defines) const
{
    std::string result = line;

    // Replace defines first (longest first to avoid partial matches)
    auto sortedDefines = defines;
    std::sort(sortedDefines.begin(), sortedDefines.end(),
        [](const Define& a, const Define& b) { return a.name.size() > b.name.size(); });

    for (auto& d : sortedDefines) {
        size_t pos = 0;
        while ((pos = result.find(d.name, pos)) != std::string::npos) {
            result.replace(pos, d.name.size(), d.value);
            pos += d.value.size();
        }
    }

    // Replace alloc names with hex addresses
    for (auto& a : allocs) {
        if (a.address == 0) continue;
        char addr[32];
        snprintf(addr, sizeof(addr), "0x%lx", a.address);
        size_t pos = 0;
        while ((pos = result.find(a.name, pos)) != std::string::npos) {
            result.replace(pos, a.name.size(), addr);
            pos += strlen(addr);
        }
    }

    // Replace label names with hex addresses
    for (auto& l : labels) {
        if (l.address == 0) continue;
        char addr[32];
        snprintf(addr, sizeof(addr), "0x%lx", l.address);
        size_t pos = 0;
        while ((pos = result.find(l.name, pos)) != std::string::npos) {
            result.replace(pos, l.name.size(), addr);
            pos += strlen(addr);
        }
    }

    return result;
}

bool AutoAssembler::resolveForwardLabels(const std::vector<std::string>& asmLines,
    const std::vector<Alloc>& allocs, std::vector<Label>& labels,
    const std::vector<Define>& defines, ProcessHandle& proc,
    std::string& error)
{
    auto substituteForSizing = [&](const std::string& line, uintptr_t currentAddr) {
        auto result = substituteSymbols(line, allocs, labels, defines);
        auto placeholder = formatHexLiteral(currentAddr);

        for (const auto& l : labels) {
            if (l.address != 0)
                continue;
            size_t pos = 0;
            while ((pos = result.find(l.name, pos)) != std::string::npos) {
                result.replace(pos, l.name.size(), placeholder);
                pos += placeholder.size();
            }
        }
        return result;
    };

    constexpr size_t maxPasses = 8;
    for (size_t pass = 0; pass < maxPasses; ++pass) {
        uintptr_t currentAddr = 0;
        bool changed = false;

        for (const auto& rawLine : asmLines) {
            auto trimmedLine = trim(rawLine);
            if (trimmedLine.empty())
                continue;

            if (isSimpleLabelDefinition(trimmedLine)) {
                auto labelName = trimmedLine.substr(0, trimmedLine.size() - 1);
                bool handledLabel = false;

                for (const auto& a : allocs) {
                    if (a.name == labelName) {
                        currentAddr = a.address;
                        handledLabel = true;
                        break;
                    }
                }
                if (handledLabel)
                    continue;

                for (auto& l : labels) {
                    if (l.name == labelName) {
                        if (currentAddr == 0) {
                            error = "Label has no active assembly address: " + labelName;
                            return false;
                        }
                        if (l.address != currentAddr) {
                            l.address = currentAddr;
                            changed = true;
                        }
                        handledLabel = true;
                        break;
                    }
                }
                if (handledLabel)
                    continue;

                auto targetAddr = resolveAddress(labelName, allocs, labels, defines);
                if (targetAddr == 0) {
                    error = "Unresolved auto-assembler target: " + labelName;
                    return false;
                }
                currentAddr = targetAddr;
                continue;
            }

            if (startsWith(trimmedLine, "__FULLACCESS__:") ||
                startsWith(trimmedLine, "__ASSERT__:") ||
                startsWith(trimmedLine, "__UNREGISTERSYMBOL__:") ||
                startsWith(trimmedLine, "__DEALLOC__:") ||
                startsWith(trimmedLine, "__CREATETHREAD__:") ||
                startsWith(trimmedLine, "__CREATETHREADANDWAIT__:") ||
                startsWith(trimmedLine, "__LOADBINARY__:") ||
                startsWith(trimmedLine, "__LOADLIBRARY__:")) {
                continue;
            }

            if (currentAddr == 0) {
                error = "No active assembly address for line: " + trimmedLine;
                return false;
            }

            if (startsWith(trimmedLine, "__REASSEMBLE__:")) {
                auto addrExpr = trimmedLine.substr(15);
                auto addr = resolveAddress(addrExpr, allocs, labels, defines);
                if (!addr) {
                    error = "Invalid REASSEMBLE target: " + addrExpr;
                    return false;
                }

                uint8_t instrBuf[16];
                auto rr = proc.read(addr, instrBuf, sizeof(instrBuf));
                if (!rr || *rr == 0) {
                    error = "REASSEMBLE read failed at " + addrExpr;
                    return false;
                }

                Disassembler dis(Arch::X86_64);
                auto insns = dis.disassemble(addr, {instrBuf, *rr}, 1);
                if (insns.empty()) {
                    error = "REASSEMBLE disassembly failed at " + addrExpr;
                    return false;
                }

                auto asmCode = insns[0].mnemonic + " " + insns[0].operands;
                auto asmResult = asm64_.assemble(asmCode, currentAddr);
                if (!asmResult) {
                    error = "REASSEMBLE sizing failed at " + addrExpr + ": " + asmResult.error();
                    return false;
                }
                currentAddr += asmResult->size();
                continue;
            }

            if (startsWith(trimmedLine, "__READMEM__:")) {
                auto args = trimmedLine.substr(12);
                auto comma = args.find(',');
                if (comma == std::string::npos) {
                    error = "READMEM requires address and size";
                    return false;
                }

                auto sizeStr = trim(args.substr(comma + 1));
                try {
                    currentAddr += std::stoull(sizeStr, nullptr, 0);
                } catch (...) {
                    error = "Invalid READMEM size: " + sizeStr;
                    return false;
                }
                continue;
            }

            if (startsWith(trimmedLine, "__FILLMEM__:")) {
                continue;
            }

            if (startsWith(trimmedLine, "__NOP__:")) {
                auto countExpr = trim(trimmedLine.substr(8));
                size_t count = 1;
                if (!parseNopCount(countExpr, count, error))
                    return false;
                currentAddr += count;
                continue;
            }

            if (startsWith(trimmedLine, "__DS__:")) {
                auto text = stripOptionalQuotes(trimmedLine.substr(7));
                if (text.empty()) {
                    error = "DS requires a string";
                    return false;
                }
                currentAddr += text.size();
                continue;
            }

            auto upper = toUpper(trimmedLine);
            if (startsWith(upper, "DB ") || startsWith(upper, "DW ") ||
                startsWith(upper, "DD ") || startsWith(upper, "DQ ")) {
                auto op = upper.substr(0, 2);
                auto dataStr = trim(trimmedLine.substr(3));
                std::vector<uint8_t> dataBytes;
                std::string parseError;
                if (!parseDataDirective(op, dataStr, dataBytes, parseError)) {
                    error = parseError;
                    return false;
                }
                currentAddr += dataBytes.size();
                continue;
            }

            auto substituted = substituteForSizing(trimmedLine, currentAddr);
            auto asmResult = asm64_.assemble(substituted, currentAddr);
            if (!asmResult) {
                error = "Assembly sizing error at " + formatHexLiteral(currentAddr) +
                    ": " + asmResult.error() + "\n  Line: " + trimmedLine;
                return false;
            }
            currentAddr += asmResult->size();
        }

        if (!changed)
            return true;
    }

    error = "Forward label resolution did not converge";
    return false;
}

// ── Symbol management ──

void AutoAssembler::registerSymbol(const std::string& name, uintptr_t address) {
    globalSymbols_[name] = address;
}

void AutoAssembler::unregisterSymbol(const std::string& name) {
    globalSymbols_.erase(name);
}

uintptr_t AutoAssembler::resolveSymbol(const std::string& name) const {
    auto it = globalSymbols_.find(name);
    return it != globalSymbols_.end() ? it->second : 0;
}

void AutoAssembler::registerCommand(const std::string& name, CustomCommandHandler handler) {
    auto key = normalizeCommandName(name);
    if (key.empty() || !handler)
        return;
    customCommands_[key] = std::move(handler);
}

void AutoAssembler::unregisterCommand(const std::string& name) {
    customCommands_.erase(normalizeCommandName(name));
}

void AutoAssembler::addPreprocessorHook(ScriptHook hook) {
    if (hook)
        preprocessorHooks_.push_back(std::move(hook));
}

void AutoAssembler::addPostprocessorHook(ScriptHook hook) {
    if (hook)
        postprocessorHooks_.push_back(std::move(hook));
}

void AutoAssembler::clearPreprocessorHooks() {
    preprocessorHooks_.clear();
}

void AutoAssembler::clearPostprocessorHooks() {
    postprocessorHooks_.clear();
}

// ── Main execution ──

AutoAsmResult AutoAssembler::execute(ProcessHandle& proc, const std::string& script) {
    AutoAsmResult result;
    result.success = false;

    // Extract ENABLE section
    auto enableCode = extractSection(script, "ENABLE");
    if (enableCode.empty()) {
        // No sections — treat entire script as enable
        enableCode = script;
    }

    if (!runScriptHooks(preprocessorHooks_, enableCode, result.log, result.error, "preprocessor"))
        return result;

    std::string expandedEnableCode;
    if (!expandStructDefinitions(enableCode, expandedEnableCode, result.log, result.error))
        return result;
    enableCode = std::move(expandedEnableCode);

    if (!runScriptHooks(postprocessorHooks_, enableCode, result.log, result.error, "postprocessor"))
        return result;

    // ── Phase 1: Parse directives ──
    std::vector<Alloc> allocs;
    std::vector<Label> labels;
    std::vector<Define> defines;
    std::vector<std::string> registeredSymbols;
    std::vector<std::string> asmLines;

    std::istringstream ss(enableCode);
    std::string line;
    while (std::getline(ss, line)) {
        if (!parseLine(line, allocs, labels, defines, registeredSymbols, asmLines, result.log, &proc, result.error))
            return result;
    }

    // ── Phase 2: Allocate memory ──
    for (auto& a : allocs) {
        auto r = proc.allocate(a.size, MemProt::All, a.preferred);
        if (r) {
            a.address = *r;
            result.disableInfo.allocs.push_back({a.name, a.address, a.size});
            knownAllocations_[a.name] = {a.name, a.address, a.size};
            result.log.push_back("Allocated " + a.name + " at 0x" +
                ([&]{ char b[32]; snprintf(b, 32, "%lx", a.address); return std::string(b); })());
        } else {
            result.error = "Failed to allocate memory for " + a.name;
            return result;
        }
    }

    if (!resolveForwardLabels(asmLines, allocs, labels, defines, proc, result.error))
        return result;

    // ── Phase 3: Assemble and inject ──
    uintptr_t currentAddr = 0;
    std::string currentLabel;
    struct DeferredThread {
        std::string addressExpr;
        bool wait = false;
        int timeoutMs = 5000;
    };
    std::vector<DeferredThread> deferredThreads;

    for (auto& rawLine : asmLines) {
        auto trimmedLine = trim(rawLine);

        // Check for label definition (name:)
        if (isSimpleLabelDefinition(trimmedLine)) {
            auto labelName = trimmedLine.substr(0, trimmedLine.size() - 1);

            bool handledLabel = false;

            // Is this an alloc name? Set currentAddr to that block.
            for (auto& a : allocs) {
                if (a.name == labelName) {
                    currentAddr = a.address;
                    handledLabel = true;
                    break;
                }
            }
            if (handledLabel) continue;

            // Is this a declared internal label? Bind it to the active block address.
            for (auto& l : labels) {
                if (l.name == labelName) {
                    if (currentAddr == 0) {
                        result.error = "Label has no active assembly address: " + labelName;
                        return result;
                    }
                    l.address = currentAddr;
                    handledLabel = true;
                    break;
                }
            }
            if (handledLabel) continue;

            // Otherwise this must be a target address expression (game.exe+1234:).
            auto targetAddr = resolveAddress(labelName, allocs, labels, defines);
            if (targetAddr == 0) {
                result.error = "Unresolved auto-assembler target: " + labelName;
                return result;
            }
            currentAddr = targetAddr;
            continue;
        }

        // Handle special deferred directives
        if (startsWith(trimmedLine, "__FULLACCESS__:")) {
            auto args = trimmedLine.substr(15);
            auto comma = args.find(',');
            if (comma == std::string::npos) {
                result.error = "FULLACCESS requires address and size";
                return result;
            }

            auto addrExpr = trim(args.substr(0, comma));
            auto sizeStr = trim(args.substr(comma + 1));
            auto addr = resolveAddress(addrExpr, allocs, labels, defines);
            size_t size = 0;
            try {
                size = std::stoull(sizeStr, nullptr, 0);
            } catch (...) {
                result.error = "Invalid FULLACCESS size: " + sizeStr;
                return result;
            }

            if (!addr || size == 0) {
                result.error = "Invalid FULLACCESS target: " + addrExpr;
                return result;
            }

            auto protectResult = proc.protect(addr, size, MemProt::All);
            if (!protectResult) {
                result.error = "FULLACCESS failed at " + addrExpr + ": " + protectResult.error().message();
                return result;
            }
            result.log.push_back("FULLACCESS: " + addrExpr + " size=" + std::to_string(size));
            continue;
        }
        if (startsWith(trimmedLine, "__ASSERT__:")) {
            auto args = trimmedLine.substr(11);
            auto comma = args.find(',');
            if (comma == std::string::npos) {
                result.error = "ASSERT requires address and bytes";
                return result;
            }

            auto addrExpr = trim(args.substr(0, comma));
            auto bytesStr = trim(args.substr(comma + 1));
            auto addr = resolveAddress(addrExpr, allocs, labels, defines);
            if (!addr) {
                result.error = "Invalid ASSERT target: " + addrExpr;
                return result;
            }

            if (!bytesStr.empty() && bytesStr.front() == '"') bytesStr = bytesStr.substr(1);
            if (!bytesStr.empty() && bytesStr.back() == '"') bytesStr.pop_back();

            ScanConfig pattern;
            pattern.parseAOB(bytesStr);
            if (pattern.byteArray.empty()) {
                result.error = "ASSERT has no bytes: " + bytesStr;
                return result;
            }

            std::vector<uint8_t> current(pattern.byteArray.size());
            auto readResult = proc.read(addr, current.data(), current.size());
            if (!readResult || *readResult < current.size()) {
                result.error = "ASSERT read failed at " + addrExpr;
                return result;
            }

            for (size_t i = 0; i < pattern.byteArray.size(); ++i) {
                if (i < pattern.byteArrayMask.size() && !pattern.byteArrayMask[i])
                    continue;
                if (current[i] != pattern.byteArray[i]) {
                    char expected[8];
                    char actual[8];
                    snprintf(expected, sizeof(expected), "%02x", pattern.byteArray[i]);
                    snprintf(actual, sizeof(actual), "%02x", current[i]);
                    result.error = "ASSERT failed at " + addrExpr + "+" + std::to_string(i) +
                        ": expected " + expected + ", got " + actual;
                    return result;
                }
            }

            result.log.push_back("ASSERT OK: " + addrExpr);
            continue;
        }
        if (startsWith(trimmedLine, "__UNREGISTERSYMBOL__:")) {
            auto args = trimmedLine.substr(21);
            std::istringstream symbolStream(args);
            std::string name;
            while (std::getline(symbolStream, name, ',')) {
                name = trim(name);
                if (name.empty()) continue;
                globalSymbols_.erase(name);
                result.disableInfo.symbols.erase(name);
                result.log.push_back("UNREGISTERSYMBOL: " + name);
            }
            continue;
        }
        if (startsWith(trimmedLine, "__DEALLOC__:")) {
            auto args = trimmedLine.substr(12);
            std::istringstream allocStream(args);
            std::string name;
            while (std::getline(allocStream, name, ',')) {
                name = trim(name);
                if (name.empty()) continue;

                auto it = knownAllocations_.find(name);
                if (it == knownAllocations_.end()) {
                    result.log.push_back("DEALLOC: " + name + " not tracked");
                    continue;
                }

                auto freeResult = proc.free(it->second.address, it->second.size);
                if (!freeResult) {
                    result.error = "DEALLOC failed for " + name + ": " + freeResult.error().message();
                    return result;
                }

                result.disableInfo.allocs.erase(
                    std::remove_if(result.disableInfo.allocs.begin(), result.disableInfo.allocs.end(),
                        [&](const DisableInfo::AllocEntry& alloc) { return alloc.name == name; }),
                    result.disableInfo.allocs.end());
                result.log.push_back("DEALLOC: " + name);
                knownAllocations_.erase(it);
            }
            continue;
        }

        if (startsWith(trimmedLine, "__CREATETHREAD__:")) {
            deferredThreads.push_back({trim(trimmedLine.substr(17)), false, 0});
            result.log.push_back("Deferred: " + trimmedLine);
            continue;
        }
        if (startsWith(trimmedLine, "__CREATETHREADANDWAIT__:")) {
            auto args = trimmedLine.substr(24);
            auto parts = splitArgs(args, 2);
            if (parts.empty() || parts[0].empty()) {
                result.error = "CREATETHREADANDWAIT requires an address";
                return result;
            }

            int timeoutMs = 5000;
            if (parts.size() > 1 && !parts[1].empty()) {
                try {
                    timeoutMs = std::stoi(parts[1], nullptr, 0);
                } catch (...) {
                    result.error = "Invalid CREATETHREADANDWAIT timeout: " + parts[1];
                    return result;
                }
            }
            deferredThreads.push_back({trim(parts[0]), true, timeoutMs});
            result.log.push_back("Deferred: " + trimmedLine);
            continue;
        }

        if (startsWith(trimmedLine, "__LOADBINARY__:")) {
            auto args = trimmedLine.substr(15);
            auto parts = splitArgs(args, 2);
            if (parts.size() != 2) {
                result.error = "LOADBINARY requires address and filename";
                return result;
            }

            auto addrExpr = trim(parts[0]);
            auto filename = stripOptionalQuotes(parts[1]);
            auto addr = resolveAddress(addrExpr, allocs, labels, defines);
            if (!addr) {
                result.error = "Invalid LOADBINARY target: " + addrExpr;
                return result;
            }

            std::ifstream binFile(filename, std::ios::binary);
            if (!binFile) {
                result.error = "LOADBINARY file not found: " + filename;
                return result;
            }

            std::vector<uint8_t> data((std::istreambuf_iterator<char>(binFile)), {});
            if (data.empty()) {
                result.error = "LOADBINARY file is empty: " + filename;
                return result;
            }

            std::vector<uint8_t> orig(data.size());
            auto readResult = proc.read(addr, orig.data(), orig.size());
            if (!readResult || *readResult < orig.size()) {
                result.error = "LOADBINARY original-byte read failed at " + addrExpr;
                return result;
            }

            result.disableInfo.originals.push_back({addr, orig});
            auto writeResult = proc.write(addr, data.data(), data.size());
            if (!writeResult || *writeResult < data.size()) {
                result.error = "LOADBINARY write failed at " + addrExpr;
                return result;
            }

            result.log.push_back("LOADBINARY: " + filename + " -> " + addrExpr);
            continue;
        }

        if (startsWith(trimmedLine, "__LOADLIBRARY__:")) {
            auto path = stripOptionalQuotes(trimmedLine.substr(16));
            if (path.empty()) {
                result.error = "LOADLIBRARY requires a shared library path";
                return result;
            }
            if (!std::filesystem::exists(path)) {
                result.error = "LOADLIBRARY file not found: " + path;
                return result;
            }

            SymbolResolver resolver;
            resolver.loadProcess(proc);
            auto injectResult = os::injectLibrary(proc, resolver, path);
            if (!injectResult) {
                result.error = "LOADLIBRARY failed for " + path + ": " + injectResult.error();
                return result;
            }

            result.log.push_back("LOADLIBRARY: " + path + " handle=0x" + formatHex(*injectResult));
            continue;
        }

        if (currentAddr == 0) {
            result.error = "No active assembly address for line: " + trimmedLine;
            return result;
        }
        if (startsWith(trimmedLine, "__REASSEMBLE__:")) {
            auto addrExpr = trimmedLine.substr(15);
            auto addr = resolveAddress(addrExpr, allocs, labels, defines);
            if (addr && &proc) {
                // Read and disassemble the instruction, then re-emit as bytes
                uint8_t instrBuf[16];
                auto rr = proc.read(addr, instrBuf, sizeof(instrBuf));
                if (rr && *rr > 0) {
                    Disassembler dis(Arch::X86_64);
                    auto insns = dis.disassemble(addr, {instrBuf, *rr}, 1);
                    if (!insns.empty()) {
                        // Assemble the instruction at the current address
                        auto asmCode = insns[0].mnemonic + " " + insns[0].operands;
                        auto asmResult = asm64_.assemble(asmCode, currentAddr);
                        if (asmResult && !asmResult->empty()) {
                            std::vector<uint8_t> orig(asmResult->size());
                            proc.read(currentAddr, orig.data(), orig.size());
                            result.disableInfo.originals.push_back({currentAddr, orig});
                            proc.write(currentAddr, asmResult->data(), asmResult->size());
                            currentAddr += asmResult->size();
                        }
                    }
                }
            }
            continue;
        }
        if (startsWith(trimmedLine, "__READMEM__:")) {
            auto args = trimmedLine.substr(12);
            auto comma = args.find(',');
            if (comma != std::string::npos && &proc) {
                auto addrExpr = trim(args.substr(0, comma));
                auto sizeStr = trim(args.substr(comma + 1));
                auto addr = resolveAddress(addrExpr, allocs, labels, defines);
                size_t sz = std::stoul(sizeStr);
                if (addr && sz > 0) {
                    std::vector<uint8_t> mem(sz);
                    auto rr = proc.read(addr, mem.data(), sz);
                    if (rr) {
                        std::vector<uint8_t> orig(*rr);
                        proc.read(currentAddr, orig.data(), orig.size());
                        result.disableInfo.originals.push_back({currentAddr, orig});
                        proc.write(currentAddr, mem.data(), *rr);
                        currentAddr += *rr;
                    }
                }
            }
            continue;
        }
        if (startsWith(trimmedLine, "__FILLMEM__:")) {
            auto args = trimmedLine.substr(12);
            auto parts = splitArgs(args, 3);
            if (parts.size() != 3) {
                result.error = "FILLMEM requires address, size, and value";
                return result;
            }

            auto addr = resolveAddress(parts[0], allocs, labels, defines);
            size_t size = 0;
            uint64_t value = 0;
            try {
                size = std::stoull(trim(parts[1]), nullptr, 0);
                value = std::stoull(trim(parts[2]), nullptr, 16);
            } catch (...) {
                result.error = "Invalid FILLMEM argument";
                return result;
            }
            if (!addr || size == 0 || value > 0xff) {
                result.error = "Invalid FILLMEM target or value";
                return result;
            }

            std::vector<uint8_t> orig(size);
            proc.read(addr, orig.data(), orig.size());
            result.disableInfo.originals.push_back({addr, orig});

            std::vector<uint8_t> data(size, static_cast<uint8_t>(value));
            proc.write(addr, data.data(), data.size());
            result.log.push_back("FILLMEM: " + parts[0] + " size=" + std::to_string(size));
            continue;
        }
        if (startsWith(trimmedLine, "__NOP__:")) {
            auto countExpr = trim(trimmedLine.substr(8));
            size_t count = 1;
            if (!parseNopCount(countExpr, count, result.error))
                return result;

            std::vector<uint8_t> orig(count);
            proc.read(currentAddr, orig.data(), orig.size());
            result.disableInfo.originals.push_back({currentAddr, orig});

            std::vector<uint8_t> data(count, 0x90);
            proc.write(currentAddr, data.data(), data.size());
            currentAddr += data.size();
            continue;
        }
        if (startsWith(trimmedLine, "__DS__:")) {
            auto text = stripOptionalQuotes(trimmedLine.substr(7));
            if (text.empty()) {
                result.error = "DS requires a string";
                return result;
            }

            std::vector<uint8_t> data(text.begin(), text.end());
            std::vector<uint8_t> orig(data.size());
            proc.read(currentAddr, orig.data(), orig.size());
            result.disableInfo.originals.push_back({currentAddr, orig});

            proc.write(currentAddr, data.data(), data.size());
            currentAddr += data.size();
            continue;
        }

        // Handle db/dw/dd/dq directives
        auto upper = toUpper(trimmedLine);
        if (startsWith(upper, "DB ") || startsWith(upper, "DW ") ||
            startsWith(upper, "DD ") || startsWith(upper, "DQ ")) {

            auto op = upper.substr(0, 2);
            auto dataStr = trim(trimmedLine.substr(3));
            std::vector<uint8_t> dataBytes;
            std::string parseError;
            if (!parseDataDirective(op, dataStr, dataBytes, parseError)) {
                result.error = parseError;
                return result;
            }

            if (!dataBytes.empty()) {
                // Save original bytes
                std::vector<uint8_t> orig(dataBytes.size());
                proc.read(currentAddr, orig.data(), orig.size());
                result.disableInfo.originals.push_back({currentAddr, orig});

                proc.write(currentAddr, dataBytes.data(), dataBytes.size());
                currentAddr += dataBytes.size();
            }
            continue;
        }

        // Substitute symbols in assembly line
        auto substituted = substituteSymbols(trimmedLine, allocs, labels, defines);

        // Assemble
        auto asmResult = asm64_.assemble(substituted, currentAddr);
        if (!asmResult) {
            result.error = "Assembly error at 0x" +
                ([&]{ char b[32]; snprintf(b, 32, "%lx", currentAddr); return std::string(b); })() +
                ": " + asmResult.error() + "\n  Line: " + trimmedLine;
            // Don't return — try to continue
            result.log.push_back("ERROR: " + result.error);
            continue;
        }

        auto& bytes = *asmResult;
        if (!bytes.empty()) {
            // Save original bytes
            std::vector<uint8_t> orig(bytes.size());
            proc.read(currentAddr, orig.data(), orig.size());
            result.disableInfo.originals.push_back({currentAddr, orig});

            // Write new bytes
            proc.write(currentAddr, bytes.data(), bytes.size());
            currentAddr += bytes.size();
        }
    }

    if (!deferredThreads.empty()) {
        SymbolResolver resolver;
        resolver.loadProcess(proc);

        for (const auto& thread : deferredThreads) {
            auto addr = resolveAddress(thread.addressExpr, allocs, labels, defines);
            if (!addr) {
                result.error = "Invalid CREATETHREAD target: " + thread.addressExpr;
                return result;
            }

            auto threadResult = os::createRemoteThread(proc, resolver, addr, thread.wait, thread.timeoutMs);
            if (!threadResult) {
                result.error = "CREATETHREAD failed for " + thread.addressExpr + ": " + threadResult.error();
                return result;
            }

            auto info = *threadResult;
            if (info.stackAddress)
                result.disableInfo.allocs.push_back({
                    "__threadstack_" + std::to_string(info.tid), info.stackAddress, info.stackSize});

            result.log.push_back(std::string(thread.wait ? "CREATETHREADANDWAIT" : "CREATETHREAD") +
                ": " + thread.addressExpr + " handle=0x" + formatHex(info.handle));

            if (thread.wait && !info.completed) {
                result.error = "CREATETHREADANDWAIT timed out for " + thread.addressExpr;
                return result;
            }
        }
    }

    // ── Phase 4: Register symbols ──
    for (auto& sym : registeredSymbols) {
        uintptr_t addr = resolveAddress(sym, allocs, labels, defines);
        if (addr) {
            globalSymbols_[sym] = addr;
            result.disableInfo.symbols[sym] = addr;
        }
    }

    result.success = result.error.empty();
    return result;
}

AutoAsmResult AutoAssembler::disable(ProcessHandle& proc, const std::string& script, const DisableInfo& info) {
    AutoAsmResult result;

    // Restore original bytes (in reverse order)
    for (auto it = info.originals.rbegin(); it != info.originals.rend(); ++it) {
        proc.write(it->address, it->bytes.data(), it->bytes.size());
    }

    // Free allocated memory
    for (auto& a : info.allocs) {
        proc.free(a.address, a.size);
        knownAllocations_.erase(a.name);
    }

    // Unregister symbols
    for (auto& [name, _] : info.symbols) {
        globalSymbols_.erase(name);
    }

    result.success = true;
    result.log.push_back("Disabled: restored " + std::to_string(info.originals.size()) +
        " patches, freed " + std::to_string(info.allocs.size()) + " allocations");
    return result;
}

AutoAsmResult AutoAssembler::check(const std::string& script) {
    AutoAsmResult result;
    // Parse without a process — syntax check only
    auto enableCode = extractSection(script, "ENABLE");
    if (enableCode.empty()) enableCode = script;

    if (!runScriptHooks(preprocessorHooks_, enableCode, result.log, result.error, "preprocessor"))
        return result;

    std::string expandedEnableCode;
    if (!expandStructDefinitions(enableCode, expandedEnableCode, result.log, result.error))
        return result;
    enableCode = std::move(expandedEnableCode);

    if (!runScriptHooks(postprocessorHooks_, enableCode, result.log, result.error, "postprocessor"))
        return result;

    std::vector<Alloc> allocs;
    std::vector<Label> labels;
    std::vector<Define> defines;
    std::vector<std::string> registeredSymbols;
    std::vector<std::string> asmLines;

    std::istringstream ss(enableCode);
    std::string line;
    while (std::getline(ss, line)) {
        if (!parseLine(line, allocs, labels, defines, registeredSymbols, asmLines, result.log, nullptr, result.error))
            return result;
    }

    result.success = true;
    result.log.push_back("Syntax OK: " + std::to_string(allocs.size()) + " allocs, " +
        std::to_string(labels.size()) + " labels, " + std::to_string(asmLines.size()) + " asm lines");
    return result;
}

} // namespace ce
