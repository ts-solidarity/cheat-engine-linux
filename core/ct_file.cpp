#include "core/ct_file.hpp"
#include <fstream>
#include <sstream>
#include <cstring>

// Simple XML writer/reader (no external dependency)
namespace ce {

// ── XML writing helpers ──
static std::string xmlEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            default:   out += c;
        }
    }
    return out;
}

static std::string typeToStr(ValueType vt) {
    switch (vt) {
        case ValueType::Byte:    return "0";
        case ValueType::Int16:   return "1";
        case ValueType::Int32:   return "2";
        case ValueType::Int64:   return "3";
        case ValueType::Float:   return "4";
        case ValueType::Double:  return "5";
        case ValueType::String:  return "6";
        case ValueType::ByteArray: return "8";
        case ValueType::Binary:  return "9";
        case ValueType::All:     return "10";
        default: return "2";
    }
}

static ValueType strToType(const std::string& s) {
    int v = std::atoi(s.c_str());
    switch (v) {
        case 0:  return ValueType::Byte;
        case 1:  return ValueType::Int16;
        case 2:  return ValueType::Int32;
        case 3:  return ValueType::Int64;
        case 4:  return ValueType::Float;
        case 5:  return ValueType::Double;
        case 6:  return ValueType::String;
        case 8:  return ValueType::ByteArray;
        case 9:  return ValueType::Binary;
        case 10: return ValueType::All;
        default: return ValueType::Int32;
    }
}

// ── Save as CE-compatible XML ──

bool CheatTable::save(const std::string& path) const {
    std::ofstream f(path);
    if (!f) return false;

    f << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    f << "<CheatTable>\n";
    f << "  <CheatTableVersion>45</CheatTableVersion>\n";

    if (!gameName.empty())
        f << "  <GameName>" << xmlEscape(gameName) << "</GameName>\n";
    if (!author.empty())
        f << "  <Author>" << xmlEscape(author) << "</Author>\n";
    if (!comment.empty())
        f << "  <Comment>" << xmlEscape(comment) << "</Comment>\n";

    if (!luaScript.empty()) {
        f << "  <LuaScript>" << xmlEscape(luaScript) << "</LuaScript>\n";
    }

    f << "  <CheatEntries>\n";
    for (auto& e : entries) {
        f << "    <CheatEntry>\n";
        f << "      <ID>" << e.id << "</ID>\n";
        f << "      <Description>" << xmlEscape(e.description) << "</Description>\n";

        if (e.isGroup) {
            f << "      <GroupHeader>1</GroupHeader>\n";
        } else {
            char addr[32];
            snprintf(addr, sizeof(addr), "%lx", e.address);
            f << "      <Address>" << addr << "</Address>\n";
            f << "      <VariableType>" << typeToStr(e.type) << "</VariableType>\n";
            if (!e.value.empty())
                f << "      <Value>" << xmlEscape(e.value) << "</Value>\n";
        }

        if (e.active)
            f << "      <Activated>1</Activated>\n";

        if (!e.autoAsmScript.empty()) {
            f << "      <AssemblerScript>" << xmlEscape(e.autoAsmScript) << "</AssemblerScript>\n";
        }

        if (!e.luaScript.empty()) {
            f << "      <LuaScript>" << xmlEscape(e.luaScript) << "</LuaScript>\n";
        }

        if (!e.color.empty())
            f << "      <Color>" << e.color << "</Color>\n";

        if (!e.dropdownList.empty())
            f << "      <DropdownList>" << xmlEscape(e.dropdownList) << "</DropdownList>\n";

        if (!e.hotkeyKeys.empty())
            f << "      <Hotkeys>" << xmlEscape(e.hotkeyKeys) << "</Hotkeys>\n";

        f << "    </CheatEntry>\n";
    }
    f << "  </CheatEntries>\n";
    f << "</CheatTable>\n";

    return true;
}

// ── Simple XML tag parser ──
static std::string getTag(const std::string& xml, const std::string& tag) {
    auto openTag = "<" + tag + ">";
    auto closeTag = "</" + tag + ">";
    auto start = xml.find(openTag);
    if (start == std::string::npos) return "";
    start += openTag.size();
    auto end = xml.find(closeTag, start);
    if (end == std::string::npos) return "";
    return xml.substr(start, end - start);
}

static std::string xmlUnescape(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '&') {
            if (s.substr(i, 4) == "&lt;") { out += '<'; i += 3; }
            else if (s.substr(i, 4) == "&gt;") { out += '>'; i += 3; }
            else if (s.substr(i, 5) == "&amp;") { out += '&'; i += 4; }
            else if (s.substr(i, 6) == "&quot;") { out += '"'; i += 5; }
            else out += s[i];
        } else {
            out += s[i];
        }
    }
    return out;
}

bool CheatTable::load(const std::string& path) {
    std::ifstream f(path);
    if (!f) return false;

    std::string xml((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    gameName = xmlUnescape(getTag(xml, "GameName"));
    author = xmlUnescape(getTag(xml, "Author"));
    comment = xmlUnescape(getTag(xml, "Comment"));
    luaScript = xmlUnescape(getTag(xml, "LuaScript"));

    // Parse CheatEntries
    entries.clear();
    std::string entriesXml = getTag(xml, "CheatEntries");
    size_t pos = 0;
    while (true) {
        auto entryStart = entriesXml.find("<CheatEntry>", pos);
        if (entryStart == std::string::npos) break;
        auto entryEnd = entriesXml.find("</CheatEntry>", entryStart);
        if (entryEnd == std::string::npos) break;

        std::string entryXml = entriesXml.substr(entryStart, entryEnd - entryStart + 13);

        CheatEntry e;
        auto idStr = getTag(entryXml, "ID");
        if (!idStr.empty()) e.id = std::atoi(idStr.c_str());
        e.description = xmlUnescape(getTag(entryXml, "Description"));

        auto groupHeader = getTag(entryXml, "GroupHeader");
        e.isGroup = (groupHeader == "1");

        if (!e.isGroup) {
            auto addrStr = getTag(entryXml, "Address");
            if (!addrStr.empty()) e.address = std::stoull(addrStr, nullptr, 16);
            e.type = strToType(getTag(entryXml, "VariableType"));
            e.value = xmlUnescape(getTag(entryXml, "Value"));
        }

        e.active = (getTag(entryXml, "Activated") == "1");
        e.autoAsmScript = xmlUnescape(getTag(entryXml, "AssemblerScript"));
        e.luaScript = xmlUnescape(getTag(entryXml, "LuaScript"));
        e.color = getTag(entryXml, "Color");
        e.dropdownList = xmlUnescape(getTag(entryXml, "DropdownList"));
        e.hotkeyKeys = xmlUnescape(getTag(entryXml, "Hotkeys"));

        entries.push_back(std::move(e));
        pos = entryEnd + 13;
    }

    return true;
}

// ── JSON format (our native format, simpler) ──

bool CheatTable::saveJson(const std::string& path) const {
    std::ofstream f(path);
    if (!f) return false;

    f << "{\n";
    f << "  \"game\": \"" << gameName << "\",\n";
    f << "  \"author\": \"" << author << "\",\n";
    f << "  \"entries\": [\n";
    for (size_t i = 0; i < entries.size(); ++i) {
        auto& e = entries[i];
        f << "    {";
        f << "\"id\":" << e.id;
        f << ",\"desc\":\"" << e.description << "\"";
        if (!e.isGroup) {
            char addr[32]; snprintf(addr, sizeof(addr), "0x%lx", e.address);
            f << ",\"addr\":\"" << addr << "\"";
            f << ",\"type\":" << (int)e.type;
            f << ",\"value\":\"" << e.value << "\"";
        }
        if (e.active) f << ",\"active\":true";
        if (e.isGroup) f << ",\"group\":true";
        if (!e.autoAsmScript.empty()) f << ",\"asm\":\"...\"";
        f << "}";
        if (i + 1 < entries.size()) f << ",";
        f << "\n";
    }
    f << "  ]\n}\n";
    return true;
}

bool CheatTable::loadJson(const std::string& path) {
    // Simplified JSON loading — for full support use a JSON library
    // For now, redirect to the existing JSON save/load in mainwindow
    return false;
}

} // namespace ce
