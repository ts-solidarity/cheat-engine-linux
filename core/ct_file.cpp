#include "core/ct_file.hpp"
#include <fstream>
#include <sstream>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <unordered_map>

// Simple XML writer/reader (no external dependency)
namespace ce {

static constexpr uint64_t kFnvOffset = 1469598103934665603ULL;
static constexpr uint64_t kFnvPrime = 1099511628211ULL;

static uint64_t fnv1a(const std::string& text) {
    uint64_t hash = kFnvOffset;
    for (unsigned char c : text) {
        hash ^= c;
        hash *= kFnvPrime;
    }
    return hash;
}

static uint64_t xorshift64(uint64_t& state) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

static std::vector<uint8_t> xorCrypt(const std::string& input, const std::string& password) {
    uint64_t state = fnv1a(password.empty() ? std::string("cecore") : password);
    std::vector<uint8_t> out(input.begin(), input.end());
    for (auto& byte : out)
        byte ^= static_cast<uint8_t>(xorshift64(state) & 0xff);
    return out;
}

static std::string xorDecrypt(const std::vector<uint8_t>& input, const std::string& password) {
    uint64_t state = fnv1a(password.empty() ? std::string("cecore") : password);
    std::string out(input.begin(), input.end());
    for (auto& byte : out)
        byte = static_cast<char>(static_cast<unsigned char>(byte) ^ static_cast<uint8_t>(xorshift64(state) & 0xff));
    return out;
}

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
        case ValueType::Byte:    return "Byte";
        case ValueType::Int16:   return "2 Bytes";
        case ValueType::Int32:   return "4 Bytes";
        case ValueType::Int64:   return "8 Bytes";
        case ValueType::Float:   return "Float";
        case ValueType::Double:  return "Double";
        case ValueType::String:  return "String";
        case ValueType::ByteArray: return "Array of byte";
        case ValueType::Binary:  return "Binary";
        case ValueType::Pointer: return "Pointer";
        case ValueType::Custom:  return "Custom";
        default: return "4 Bytes";
    }
}

static std::string normalizedTypeName(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c))
            out += static_cast<char>(std::tolower(c));
    }
    return out;
}

static ValueType strToType(const std::string& s) {
    bool numeric = !s.empty();
    for (unsigned char c : s) {
        if (!std::isdigit(c)) {
            numeric = false;
            break;
        }
    }
    if (numeric) {
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
            case 12: return ValueType::Custom;
            case 13: return ValueType::Pointer;
            default: return ValueType::Int32;
        }
    }

    auto type = normalizedTypeName(s);
    if (type == "byte" || type == "1byte") return ValueType::Byte;
    if (type == "2bytes" || type == "short") return ValueType::Int16;
    if (type == "4bytes" || type == "integer" || type == "int") return ValueType::Int32;
    if (type == "8bytes" || type == "long" || type == "int64") return ValueType::Int64;
    if (type == "float" || type == "single") return ValueType::Float;
    if (type == "double") return ValueType::Double;
    if (type == "string" || type == "text") return ValueType::String;
    if (type == "arrayofbyte" || type == "bytearray" || type == "aob") return ValueType::ByteArray;
    if (type == "binary" || type == "bits") return ValueType::Binary;
    if (type == "pointer") return ValueType::Pointer;
    if (type == "custom" || type == "customtype") return ValueType::Custom;
    return ValueType::Int32;
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
    if (!gameVersion.empty())
        f << "  <GameVersion>" << xmlEscape(gameVersion) << "</GameVersion>\n";
    if (!author.empty())
        f << "  <Author>" << xmlEscape(author) << "</Author>\n";
    if (!comment.empty())
        f << "  <Comment>" << xmlEscape(comment) << "</Comment>\n";

    if (!luaScript.empty()) {
        f << "  <LuaScript>" << xmlEscape(luaScript) << "</LuaScript>\n";
    }

    if (!structures.empty()) {
        f << "  <Structures>\n";
        for (const auto& s : structures) {
            f << "    <Structure>\n";
            f << "      <Name>" << xmlEscape(s.name) << "</Name>\n";
            f << "      <Size>" << s.size << "</Size>\n";
            f << "      <Elements>\n";
            for (const auto& field : s.fields) {
                f << "        <Element>\n";
                f << "          <Name>" << xmlEscape(field.name) << "</Name>\n";
                f << "          <Offset>" << field.offset << "</Offset>\n";
                f << "          <Type>" << typeToStr(field.type) << "</Type>\n";
                f << "          <Size>" << field.size << "</Size>\n";
                if (!field.displayMethod.empty())
                    f << "          <DisplayMethod>" << xmlEscape(field.displayMethod) << "</DisplayMethod>\n";
                if (!field.nestedStructure.empty())
                    f << "          <NestedStructure>" << xmlEscape(field.nestedStructure) << "</NestedStructure>\n";
                f << "        </Element>\n";
            }
            f << "      </Elements>\n";
            f << "    </Structure>\n";
        }
        f << "  </Structures>\n";
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

static std::vector<std::string> getTagBlocks(const std::string& xml, const std::string& tag) {
    std::vector<std::string> blocks;
    auto openTag = "<" + tag + ">";
    auto closeTag = "</" + tag + ">";
    size_t pos = 0;
    while (true) {
        auto start = xml.find(openTag, pos);
        if (start == std::string::npos) break;
        auto end = xml.find(closeTag, start);
        if (end == std::string::npos) break;
        blocks.push_back(xml.substr(start, end - start + closeTag.size()));
        pos = end + closeTag.size();
    }
    return blocks;
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

static std::string jsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:   out += c; break;
        }
    }
    return out;
}

struct JsonValue {
    enum class Type { Null, Bool, Number, String, Array, Object };

    Type type = Type::Null;
    bool boolValue = false;
    double numberValue = 0.0;
    std::string stringValue;
    std::vector<JsonValue> arrayValue;
    std::unordered_map<std::string, JsonValue> objectValue;
};

class JsonParser {
public:
    explicit JsonParser(const std::string& input) : input_(input) {}

    bool parse(JsonValue& out) {
        skipWs();
        if (!parseValue(out)) return false;
        skipWs();
        return pos_ == input_.size();
    }

private:
    void skipWs() {
        while (pos_ < input_.size() && std::isspace(static_cast<unsigned char>(input_[pos_])))
            ++pos_;
    }

    bool consume(char expected) {
        skipWs();
        if (pos_ >= input_.size() || input_[pos_] != expected) return false;
        ++pos_;
        return true;
    }

    bool parseValue(JsonValue& out) {
        skipWs();
        if (pos_ >= input_.size()) return false;
        char c = input_[pos_];
        if (c == '"') return parseString(out);
        if (c == '{') return parseObject(out);
        if (c == '[') return parseArray(out);
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return parseNumber(out);
        if (input_.compare(pos_, 4, "true") == 0) {
            pos_ += 4;
            out.type = JsonValue::Type::Bool;
            out.boolValue = true;
            return true;
        }
        if (input_.compare(pos_, 5, "false") == 0) {
            pos_ += 5;
            out.type = JsonValue::Type::Bool;
            out.boolValue = false;
            return true;
        }
        if (input_.compare(pos_, 4, "null") == 0) {
            pos_ += 4;
            out.type = JsonValue::Type::Null;
            return true;
        }
        return false;
    }

    bool parseString(JsonValue& out) {
        if (pos_ >= input_.size() || input_[pos_] != '"') return false;
        ++pos_;
        std::string value;
        while (pos_ < input_.size()) {
            char c = input_[pos_++];
            if (c == '"') {
                out.type = JsonValue::Type::String;
                out.stringValue = std::move(value);
                return true;
            }
            if (c != '\\') {
                value += c;
                continue;
            }
            if (pos_ >= input_.size()) return false;
            char esc = input_[pos_++];
            switch (esc) {
                case '"': value += '"'; break;
                case '\\': value += '\\'; break;
                case '/': value += '/'; break;
                case 'b': value += '\b'; break;
                case 'f': value += '\f'; break;
                case 'n': value += '\n'; break;
                case 'r': value += '\r'; break;
                case 't': value += '\t'; break;
                case 'u': {
                    if (pos_ + 4 > input_.size()) return false;
                    auto hex = input_.substr(pos_, 4);
                    pos_ += 4;
                    char* end = nullptr;
                    auto code = std::strtoul(hex.c_str(), &end, 16);
                    if (!end || *end != '\0') return false;
                    value += (code <= 0x7f) ? static_cast<char>(code) : '?';
                    break;
                }
                default:
                    return false;
            }
        }
        return false;
    }

    bool parseNumber(JsonValue& out) {
        const char* start = input_.c_str() + pos_;
        char* end = nullptr;
        double value = std::strtod(start, &end);
        if (end == start) return false;
        pos_ += static_cast<size_t>(end - start);
        out.type = JsonValue::Type::Number;
        out.numberValue = value;
        return true;
    }

    bool parseArray(JsonValue& out) {
        if (!consume('[')) return false;
        out.type = JsonValue::Type::Array;
        skipWs();
        if (pos_ < input_.size() && input_[pos_] == ']') {
            ++pos_;
            return true;
        }
        while (true) {
            JsonValue item;
            if (!parseValue(item)) return false;
            out.arrayValue.push_back(std::move(item));
            skipWs();
            if (pos_ < input_.size() && input_[pos_] == ']') {
                ++pos_;
                return true;
            }
            if (!consume(',')) return false;
        }
    }

    bool parseObject(JsonValue& out) {
        if (!consume('{')) return false;
        out.type = JsonValue::Type::Object;
        skipWs();
        if (pos_ < input_.size() && input_[pos_] == '}') {
            ++pos_;
            return true;
        }
        while (true) {
            skipWs();
            JsonValue key;
            if (!parseString(key)) return false;
            if (!consume(':')) return false;
            JsonValue value;
            if (!parseValue(value)) return false;
            out.objectValue.emplace(std::move(key.stringValue), std::move(value));
            skipWs();
            if (pos_ < input_.size() && input_[pos_] == '}') {
                ++pos_;
                return true;
            }
            if (!consume(',')) return false;
        }
    }

    const std::string& input_;
    size_t pos_ = 0;
};

static const JsonValue* getField(const JsonValue& obj, const std::string& key) {
    if (obj.type != JsonValue::Type::Object) return nullptr;
    auto it = obj.objectValue.find(key);
    return it == obj.objectValue.end() ? nullptr : &it->second;
}

static std::string jsonStringField(const JsonValue& obj, const std::string& key) {
    auto* v = getField(obj, key);
    return (v && v->type == JsonValue::Type::String) ? v->stringValue : "";
}

static bool jsonBoolField(const JsonValue& obj, const std::string& key) {
    auto* v = getField(obj, key);
    if (!v) return false;
    if (v->type == JsonValue::Type::Bool) return v->boolValue;
    if (v->type == JsonValue::Type::Number) return v->numberValue != 0.0;
    if (v->type == JsonValue::Type::String) return v->stringValue == "true" || v->stringValue == "1";
    return false;
}

static int jsonIntField(const JsonValue& obj, const std::string& key, int defaultValue = 0) {
    auto* v = getField(obj, key);
    if (!v) return defaultValue;
    if (v->type == JsonValue::Type::Number) return static_cast<int>(v->numberValue);
    if (v->type == JsonValue::Type::String) {
        try { return std::stoi(v->stringValue, nullptr, 0); } catch (...) {}
    }
    return defaultValue;
}

static size_t jsonSizeField(const JsonValue& obj, const std::string& key, size_t defaultValue = 0) {
    auto* v = getField(obj, key);
    if (!v) return defaultValue;
    if (v->type == JsonValue::Type::Number) return static_cast<size_t>(v->numberValue);
    if (v->type == JsonValue::Type::String) {
        try { return static_cast<size_t>(std::stoull(v->stringValue, nullptr, 0)); } catch (...) {}
    }
    return defaultValue;
}

static uintptr_t jsonAddressField(const JsonValue& obj, const std::string& key) {
    auto* v = getField(obj, key);
    if (!v) return 0;
    if (v->type == JsonValue::Type::Number) return static_cast<uintptr_t>(v->numberValue);
    if (v->type == JsonValue::Type::String) {
        try { return static_cast<uintptr_t>(std::stoull(v->stringValue, nullptr, 0)); } catch (...) {}
    }
    return 0;
}

static ValueType jsonValueTypeField(const JsonValue& obj) {
    auto* v = getField(obj, "type");
    if (!v) return ValueType::Int32;
    if (v->type == JsonValue::Type::Number)
        return static_cast<ValueType>(static_cast<int>(v->numberValue));
    if (v->type != JsonValue::Type::String)
        return ValueType::Int32;

    auto s = v->stringValue;
    if (s == "byte")   return ValueType::Byte;
    if (s == "i16")    return ValueType::Int16;
    if (s == "i32")    return ValueType::Int32;
    if (s == "i64")    return ValueType::Int64;
    if (s == "float")  return ValueType::Float;
    if (s == "double") return ValueType::Double;
    if (s == "string") return ValueType::String;
    if (s == "aob")    return ValueType::ByteArray;
    try { return static_cast<ValueType>(std::stoi(s, nullptr, 0)); } catch (...) {}
    return ValueType::Int32;
}

bool CheatTable::load(const std::string& path) {
    std::ifstream f(path);
    if (!f) return false;

    std::string xml((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    auto entriesStart = xml.find("<CheatEntries>");
    auto headerXml = entriesStart == std::string::npos ? xml : xml.substr(0, entriesStart);

    gameName = xmlUnescape(getTag(headerXml, "GameName"));
    gameVersion = xmlUnescape(getTag(headerXml, "GameVersion"));
    author = xmlUnescape(getTag(headerXml, "Author"));
    comment = xmlUnescape(getTag(headerXml, "Comment"));
    luaScript = xmlUnescape(getTag(headerXml, "LuaScript"));

    structures.clear();
    auto structuresXml = getTag(xml, "Structures");
    for (const auto& structureXml : getTagBlocks(structuresXml, "Structure")) {
        StructureDefinition structure;
        structure.name = xmlUnescape(getTag(structureXml, "Name"));
        auto sizeStr = getTag(structureXml, "Size");
        if (!sizeStr.empty()) {
            try { structure.size = std::stoull(sizeStr, nullptr, 0); } catch (...) {}
        }

        auto elementsXml = getTag(structureXml, "Elements");
        for (const auto& elementXml : getTagBlocks(elementsXml, "Element")) {
            StructureField field;
            field.name = xmlUnescape(getTag(elementXml, "Name"));
            auto offsetStr = getTag(elementXml, "Offset");
            auto fieldSizeStr = getTag(elementXml, "Size");
            if (!offsetStr.empty()) {
                try { field.offset = std::stoull(offsetStr, nullptr, 0); } catch (...) {}
            }
            if (!fieldSizeStr.empty()) {
                try { field.size = std::stoull(fieldSizeStr, nullptr, 0); } catch (...) {}
            }
            field.type = strToType(getTag(elementXml, "Type"));
            field.displayMethod = xmlUnescape(getTag(elementXml, "DisplayMethod"));
            field.nestedStructure = xmlUnescape(getTag(elementXml, "NestedStructure"));
            structure.fields.push_back(std::move(field));
        }

        if (!structure.name.empty() || !structure.fields.empty())
            structures.push_back(std::move(structure));
    }

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
    f << "  \"game\": \"" << jsonEscape(gameName) << "\",\n";
    f << "  \"version\": \"" << jsonEscape(gameVersion) << "\",\n";
    f << "  \"author\": \"" << jsonEscape(author) << "\",\n";
    f << "  \"comment\": \"" << jsonEscape(comment) << "\",\n";
    f << "  \"luaScript\": \"" << jsonEscape(luaScript) << "\",\n";
    f << "  \"structures\": [\n";
    for (size_t i = 0; i < structures.size(); ++i) {
        const auto& s = structures[i];
        f << "    {\"name\":\"" << jsonEscape(s.name) << "\",\"size\":" << s.size << ",\"fields\":[";
        for (size_t fieldIndex = 0; fieldIndex < s.fields.size(); ++fieldIndex) {
            const auto& field = s.fields[fieldIndex];
            f << "{\"name\":\"" << jsonEscape(field.name) << "\"";
            f << ",\"offset\":" << field.offset;
            f << ",\"type\":" << (int)field.type;
            f << ",\"size\":" << field.size;
            if (!field.displayMethod.empty())
                f << ",\"display\":\"" << jsonEscape(field.displayMethod) << "\"";
            if (!field.nestedStructure.empty())
                f << ",\"nested\":\"" << jsonEscape(field.nestedStructure) << "\"";
            f << "}";
            if (fieldIndex + 1 < s.fields.size()) f << ",";
        }
        f << "]}";
        if (i + 1 < structures.size()) f << ",";
        f << "\n";
    }
    f << "  ],\n";
    f << "  \"entries\": [\n";
    for (size_t i = 0; i < entries.size(); ++i) {
        auto& e = entries[i];
        f << "    {";
        f << "\"id\":" << e.id;
        f << ",\"desc\":\"" << jsonEscape(e.description) << "\"";
        if (!e.isGroup) {
            char addr[32]; snprintf(addr, sizeof(addr), "0x%lx", e.address);
            f << ",\"addr\":\"" << addr << "\"";
            f << ",\"type\":" << (int)e.type;
            f << ",\"value\":\"" << jsonEscape(e.value) << "\"";
        }
        if (e.active) f << ",\"active\":true";
        if (e.isGroup) f << ",\"group\":true";
        if (!e.autoAsmScript.empty()) f << ",\"asm\":\"" << jsonEscape(e.autoAsmScript) << "\"";
        if (!e.luaScript.empty()) f << ",\"lua\":\"" << jsonEscape(e.luaScript) << "\"";
        if (!e.color.empty()) f << ",\"color\":\"" << jsonEscape(e.color) << "\"";
        if (!e.dropdownList.empty()) f << ",\"dropdown\":\"" << jsonEscape(e.dropdownList) << "\"";
        if (!e.hotkeyKeys.empty()) f << ",\"hotkeys\":\"" << jsonEscape(e.hotkeyKeys) << "\"";
        if (e.parentId >= 0) f << ",\"parent\":" << e.parentId;
        f << "}";
        if (i + 1 < entries.size()) f << ",";
        f << "\n";
    }
    f << "  ]\n}\n";
    return true;
}

bool CheatTable::loadJson(const std::string& path) {
    std::ifstream f(path);
    if (!f) return false;

    std::string json((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    JsonValue root;
    if (!JsonParser(json).parse(root) || root.type != JsonValue::Type::Object)
        return false;

    gameName = jsonStringField(root, "game");
    gameVersion = jsonStringField(root, "version");
    author = jsonStringField(root, "author");
    comment = jsonStringField(root, "comment");
    luaScript = jsonStringField(root, "luaScript");

    structures.clear();
    auto* structuresValue = getField(root, "structures");
    if (structuresValue && structuresValue->type == JsonValue::Type::Array) {
        for (const auto& item : structuresValue->arrayValue) {
            if (item.type != JsonValue::Type::Object) continue;

            StructureDefinition structure;
            structure.name = jsonStringField(item, "name");
            structure.size = jsonSizeField(item, "size");

            auto* fieldsValue = getField(item, "fields");
            if (fieldsValue && fieldsValue->type == JsonValue::Type::Array) {
                for (const auto& fieldItem : fieldsValue->arrayValue) {
                    if (fieldItem.type != JsonValue::Type::Object) continue;
                    StructureField field;
                    field.name = jsonStringField(fieldItem, "name");
                    field.offset = jsonSizeField(fieldItem, "offset");
                    field.type = jsonValueTypeField(fieldItem);
                    field.size = jsonSizeField(fieldItem, "size", 4);
                    field.displayMethod = jsonStringField(fieldItem, "display");
                    field.nestedStructure = jsonStringField(fieldItem, "nested");
                    structure.fields.push_back(std::move(field));
                }
            }

            structures.push_back(std::move(structure));
        }
    }

    entries.clear();
    auto* entriesValue = getField(root, "entries");
    if (!entriesValue || entriesValue->type != JsonValue::Type::Array)
        return true;

    for (const auto& item : entriesValue->arrayValue) {
        if (item.type != JsonValue::Type::Object) continue;

        CheatEntry e;
        e.id = jsonIntField(item, "id");
        e.description = jsonStringField(item, "desc");
        e.address = jsonAddressField(item, "addr");
        e.type = jsonValueTypeField(item);
        e.value = jsonStringField(item, "value");
        e.active = jsonBoolField(item, "active");
        e.isGroup = jsonBoolField(item, "group");
        e.autoAsmScript = jsonStringField(item, "asm");
        e.luaScript = jsonStringField(item, "lua");
        e.color = jsonStringField(item, "color");
        e.dropdownList = jsonStringField(item, "dropdown");
        e.hotkeyKeys = jsonStringField(item, "hotkeys");
        e.parentId = jsonIntField(item, "parent", -1);
        entries.push_back(std::move(e));
    }

    return true;
}

bool CheatTable::saveProtected(const std::string& path, const std::string& password) const {
    auto tempPath = std::filesystem::path(path).string() + ".json.tmp";
    if (!saveJson(tempPath))
        return false;

    std::ifstream in(tempPath, std::ios::binary);
    std::string json((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    std::filesystem::remove(tempPath);
    if (json.empty())
        return false;

    auto encrypted = xorCrypt(json, password);
    std::ofstream out(path, std::ios::binary);
    if (!out)
        return false;

    out << "CETRAINER1\n";
    out << fnv1a(password) << "\n";
    out.write(reinterpret_cast<const char*>(encrypted.data()), static_cast<std::streamsize>(encrypted.size()));
    return out.good();
}

bool CheatTable::loadProtected(const std::string& path, const std::string& password) {
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return false;

    std::string magic;
    std::string hashLine;
    if (!std::getline(in, magic) || !std::getline(in, hashLine))
        return false;
    if (magic != "CETRAINER1")
        return false;

    uint64_t expectedHash = 0;
    try {
        expectedHash = std::stoull(hashLine);
    } catch (...) {
        return false;
    }
    if (expectedHash != fnv1a(password))
        return false;

    std::vector<uint8_t> encrypted((std::istreambuf_iterator<char>(in)), {});
    auto json = xorDecrypt(encrypted, password);

    auto tempPath = std::filesystem::path(path).string() + ".json.tmp";
    {
        std::ofstream out(tempPath, std::ios::binary);
        if (!out)
            return false;
        out.write(json.data(), static_cast<std::streamsize>(json.size()));
    }

    bool loaded = loadJson(tempPath);
    std::filesystem::remove(tempPath);
    return loaded;
}

} // namespace ce
