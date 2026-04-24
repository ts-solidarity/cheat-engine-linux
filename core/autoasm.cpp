#include "core/autoasm.hpp"
#include "arch/disassembler.hpp"
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <regex>
#include <string_view>

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

static bool startsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
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

void AutoAssembler::parseLine(const std::string& rawLine,
    std::vector<Alloc>& allocs, std::vector<Label>& labels,
    std::vector<Define>& defines, std::vector<std::string>& registeredSymbols,
    std::vector<std::string>& asmLines, std::vector<std::string>& log,
    ProcessHandle* proc)
{
    auto line = trim(rawLine);
    if (line.empty() || line[0] == '/' || line[0] == ';') return; // Comment

    // Strip inline comments
    auto commentPos = line.find("//");
    if (commentPos != std::string::npos) line = trim(line.substr(0, commentPos));
    if (line.empty()) return;

    auto upper = toUpper(line);

    // ALLOC(name, size [, preferred])
    if (startsWith(upper, "ALLOC(") && line.back() == ')') {
        auto args = line.substr(6, line.size() - 7);
        Alloc a;
        parseAllocArgs(args, a.name, a.size, a.preferred);
        a.address = 0;
        allocs.push_back(a);
        log.push_back("ALLOC: " + a.name + " size=" + std::to_string(a.size));
        return;
    }

    // DEALLOC — handled in disable section, skip during enable
    if (startsWith(upper, "DEALLOC(")) return;

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
        return;
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
        return;
    }

    // REGISTERSYMBOL(name)
    if (startsWith(upper, "REGISTERSYMBOL(") && line.back() == ')') {
        auto args = line.substr(15, line.size() - 16);
        std::istringstream ss(args);
        std::string name;
        while (std::getline(ss, name, ','))
            registeredSymbols.push_back(trim(name));
        return;
    }

    if (startsWith(upper, "UNREGISTERSYMBOL(") && line.back() == ')') {
        constexpr std::string_view prefix = "UNREGISTERSYMBOL(";
        auto args = line.substr(prefix.size(), line.size() - prefix.size() - 1);
        asmLines.push_back("__UNREGISTERSYMBOL__:" + args);
        return;
    }

    // FULLACCESS(address, size) — make memory writable
    if (startsWith(upper, "FULLACCESS(") && line.back() == ')') {
        auto args = line.substr(11, line.size() - 12);
        asmLines.push_back("__FULLACCESS__:" + args);
        return;
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
        return;
    }

    // AOBSCAN(name, pattern) — find pattern
    if (startsWith(upper, "AOBSCAN(") && line.back() == ')' && proc) {
        auto args = line.substr(8, line.size() - 9);
        auto comma = args.find(',');
        if (comma != std::string::npos) {
            auto name = trim(args.substr(0, comma));
            auto pattern = trim(args.substr(comma + 1));
            // Remove quotes
            if (pattern.front() == '"') pattern = pattern.substr(1);
            if (pattern.back() == '"') pattern.pop_back();

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
                d.value = "0x" + std::to_string(addr); // Will be properly formatted
                char buf[32];
                snprintf(buf, sizeof(buf), "%lx", addr);
                d.value = std::string(buf);
                defines.push_back(d);
                log.push_back("AOBSCAN: " + name + " = 0x" + std::string(buf) + " (" + std::to_string(result.count()) + " matches)");
            } else {
                log.push_back("AOBSCAN: " + name + " NOT FOUND");
            }
        }
        return;
    }

    // CREATETHREAD(address) — create remote thread at address after injection
    if (startsWith(upper, "CREATETHREAD(") && line.back() == ')') {
        auto addr = trim(line.substr(13, line.size() - 14));
        log.push_back("CREATETHREAD: " + addr + " (deferred to post-injection)");
        // Store for execution after all writes complete
        asmLines.push_back("__CREATETHREAD__:" + addr);
        return;
    }

    // CREATETHREADANDWAIT(address[, timeout])
    if (startsWith(upper, "CREATETHREADANDWAIT(") && line.back() == ')') {
        auto args = trim(line.substr(20, line.size() - 21));
        log.push_back("CREATETHREADANDWAIT: " + args);
        asmLines.push_back("__CREATETHREADANDWAIT__:" + args);
        return;
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
            while (std::getline(incFile, incLine))
                parseLine(incLine, allocs, labels, defines, registeredSymbols, asmLines, log, proc);
            log.push_back("INCLUDE: " + filename + " (loaded)");
        } else {
            log.push_back("INCLUDE: " + filename + " (NOT FOUND)");
        }
        return;
    }

    // REASSEMBLE(address) — disassemble instruction at address and re-emit it
    if (startsWith(upper, "REASSEMBLE(") && line.back() == ')' && proc) {
        auto addrExpr = trim(line.substr(11, line.size() - 12));
        asmLines.push_back("__REASSEMBLE__:" + addrExpr);
        return;
    }

    // READMEM(address, size) — read bytes from process memory, emit as db
    if (startsWith(upper, "READMEM(") && line.back() == ')') {
        auto args = trim(line.substr(8, line.size() - 9));
        asmLines.push_back("__READMEM__:" + args);
        return;
    }

    // LOADBINARY(address, filename)
    if (startsWith(upper, "LOADBINARY(") && line.back() == ')') {
        auto args = trim(line.substr(11, line.size() - 12));
        asmLines.push_back("__LOADBINARY__:" + args);
        return;
    }

    // Everything else is an assembly line or label definition
    asmLines.push_back(line);
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
            try { return std::stoull(d.value, nullptr, 16); } catch (...) {}
        }

    // Check global symbols
    auto it = globalSymbols_.find(name);
    if (it != globalSymbols_.end()) return it->second;

    // Try as hex address
    try { return std::stoull(name, nullptr, 16); } catch (...) {}

    // Try module+offset format (module.exe+1234)
    auto plus = name.find('+');
    if (plus != std::string::npos) {
        auto base = name.substr(0, plus);
        auto offset = name.substr(plus + 1);
        auto baseAddr = resolveAddress(base, allocs, labels, defines);
        if (baseAddr) {
            try { return baseAddr + std::stoull(offset, nullptr, 16); } catch (...) {}
        }
    }

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

    // ── Phase 1: Parse directives ──
    std::vector<Alloc> allocs;
    std::vector<Label> labels;
    std::vector<Define> defines;
    std::vector<std::string> registeredSymbols;
    std::vector<std::string> asmLines;

    std::istringstream ss(enableCode);
    std::string line;
    while (std::getline(ss, line))
        parseLine(line, allocs, labels, defines, registeredSymbols, asmLines, result.log, &proc);

    // ── Phase 2: Allocate memory ──
    for (auto& a : allocs) {
        auto r = proc.allocate(a.size, MemProt::All, a.preferred);
        if (r) {
            a.address = *r;
            result.disableInfo.allocs.push_back({a.name, a.address, a.size});
            result.log.push_back("Allocated " + a.name + " at 0x" +
                ([&]{ char b[32]; snprintf(b, 32, "%lx", a.address); return std::string(b); })());
        } else {
            result.error = "Failed to allocate memory for " + a.name;
            return result;
        }
    }

    // ── Phase 3: Assemble and inject ──
    uintptr_t currentAddr = 0;
    std::string currentLabel;

    for (auto& rawLine : asmLines) {
        auto trimmedLine = trim(rawLine);

        // Check for label definition (name:)
        if (trimmedLine.back() == ':' && trimmedLine.find(' ') == std::string::npos) {
            auto labelName = trimmedLine.substr(0, trimmedLine.size() - 1);

            // Is this an alloc name? Set currentAddr
            for (auto& a : allocs) {
                if (a.name == labelName) {
                    currentAddr = a.address;
                    break;
                }
            }

            // Is this a known label? Update its address
            for (auto& l : labels) {
                if (l.name == labelName) {
                    l.address = currentAddr;
                    break;
                }
            }

            // Could be an address expression (game.exe+1234:)
            if (currentAddr == 0) {
                currentAddr = resolveAddress(labelName, allocs, labels, defines);
            }
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

        if (currentAddr == 0) continue;

        if (startsWith(trimmedLine, "__CREATETHREAD__:") || startsWith(trimmedLine, "__CREATETHREADANDWAIT__:")) {
            // Defer to after all writes — store address expression for later
            result.log.push_back("Deferred: " + trimmedLine);
            continue;
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
        if (startsWith(trimmedLine, "__LOADBINARY__:")) {
            auto args = trimmedLine.substr(15);
            auto comma = args.find(',');
            if (comma != std::string::npos) {
                auto addrExpr = trim(args.substr(0, comma));
                auto filename = trim(args.substr(comma + 1));
                if (!filename.empty() && filename.front() == '"') filename = filename.substr(1);
                if (!filename.empty() && filename.back() == '"') filename.pop_back();
                std::ifstream binFile(filename, std::ios::binary);
                if (binFile) {
                    std::vector<uint8_t> data((std::istreambuf_iterator<char>(binFile)), {});
                    if (!data.empty()) {
                        std::vector<uint8_t> orig(data.size());
                        proc.read(currentAddr, orig.data(), orig.size());
                        result.disableInfo.originals.push_back({currentAddr, orig});
                        proc.write(currentAddr, data.data(), data.size());
                        currentAddr += data.size();
                    }
                }
            }
            continue;
        }

        // Handle db/dw/dd/dq directives
        auto upper = toUpper(trimmedLine);
        if (startsWith(upper, "DB ") || startsWith(upper, "DW ") ||
            startsWith(upper, "DD ") || startsWith(upper, "DQ ")) {

            auto dataStr = trim(trimmedLine.substr(3));
            std::vector<uint8_t> dataBytes;

            // Parse hex bytes
            std::istringstream dss(dataStr);
            std::string tok;
            while (dss >> tok) {
                try { dataBytes.push_back((uint8_t)std::stoul(tok, nullptr, 16)); } catch (...) {}
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

    std::vector<Alloc> allocs;
    std::vector<Label> labels;
    std::vector<Define> defines;
    std::vector<std::string> registeredSymbols;
    std::vector<std::string> asmLines;

    std::istringstream ss(enableCode);
    std::string line;
    while (std::getline(ss, line))
        parseLine(line, allocs, labels, defines, registeredSymbols, asmLines, result.log, nullptr);

    result.success = true;
    result.log.push_back("Syntax OK: " + std::to_string(allocs.size()) + " allocs, " +
        std::to_string(labels.size()) + " labels, " + std::to_string(asmLines.size()) + " asm lines");
    return result;
}

} // namespace ce
