#include "analysis/structure_tools.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>

namespace ce {

namespace {

std::string sanitizeIdentifier(const std::string& input, const std::string& fallback) {
    std::string out;
    for (unsigned char c : input) {
        if (std::isalnum(c) || c == '_')
            out.push_back(static_cast<char>(c));
        else if (!out.empty() && out.back() != '_')
            out.push_back('_');
    }

    while (!out.empty() && out.back() == '_')
        out.pop_back();
    if (out.empty())
        out = fallback;
    if (std::isdigit(static_cast<unsigned char>(out.front())))
        out.insert(out.begin(), '_');
    return out;
}

std::string cppTypeFor(ValueType type, size_t size) {
    switch (type) {
        case ValueType::Byte: return "uint8_t";
        case ValueType::Int16: return "int16_t";
        case ValueType::Int32: return "int32_t";
        case ValueType::Int64: return "int64_t";
        case ValueType::Pointer: return "uintptr_t";
        case ValueType::Float: return "float";
        case ValueType::Double: return "double";
        default:
            return "uint8_t[" + std::to_string(std::max<size_t>(1, size)) + "]";
    }
}

size_t defaultSizeFor(ValueType type, size_t explicitSize) {
    if (explicitSize != 0) return explicitSize;
    switch (type) {
        case ValueType::Byte: return 1;
        case ValueType::Int16: return 2;
        case ValueType::Int32:
        case ValueType::Float: return 4;
        case ValueType::Int64:
        case ValueType::Pointer:
        case ValueType::Double: return 8;
        default: return 1;
    }
}

} // namespace

bool saveStructureTemplate(const StructureDefinition& structure, const std::string& path) {
    CheatTable table;
    table.structures.push_back(structure);
    return table.saveJson(path);
}

std::optional<StructureDefinition> loadStructureTemplate(const std::string& path) {
    CheatTable table;
    if (!table.loadJson(path) || table.structures.empty())
        return std::nullopt;
    return table.structures.front();
}

std::string generateCppStruct(const StructureDefinition& structure) {
    auto fields = structure.fields;
    std::stable_sort(fields.begin(), fields.end(), [](const StructureField& lhs, const StructureField& rhs) {
        return lhs.offset < rhs.offset;
    });

    const std::string structName = sanitizeIdentifier(structure.name, "GeneratedStruct");
    std::ostringstream out;
    out << "#include <cstdint>\n\n";
    out << "struct " << structName << " {\n";

    size_t cursor = 0;
    size_t padIndex = 0;
    for (const auto& field : fields) {
        const size_t fieldSize = defaultSizeFor(field.type, field.size);
        if (field.offset > cursor) {
            out << "    uint8_t _pad" << padIndex++ << "[0x"
                << std::hex << (field.offset - cursor) << std::dec << "];\n";
            cursor = field.offset;
        }

        const auto type = cppTypeFor(field.type, fieldSize);
        const auto name = sanitizeIdentifier(field.name, "field_" + std::to_string(field.offset));
        auto arrayStart = type.find('[');
        if (arrayStart == std::string::npos) {
            out << "    " << type << " " << name << "; // 0x"
                << std::hex << field.offset << std::dec << "\n";
        } else {
            out << "    " << type.substr(0, arrayStart) << " " << name
                << type.substr(arrayStart) << "; // 0x"
                << std::hex << field.offset << std::dec << "\n";
        }
        cursor = std::max(cursor, field.offset + fieldSize);
    }

    if (structure.size > cursor) {
        out << "    uint8_t _pad" << padIndex++ << "[0x"
            << std::hex << (structure.size - cursor) << std::dec << "];\n";
    }

    out << "};\n";
    return out.str();
}

std::vector<StructureFieldDiff> compareStructureSnapshots(const StructureDefinition& structure,
    const std::vector<uint8_t>& before,
    const std::vector<uint8_t>& after)
{
    std::vector<StructureFieldDiff> diffs;
    for (const auto& field : structure.fields) {
        const size_t fieldSize = defaultSizeFor(field.type, field.size);
        if (fieldSize == 0 || field.offset >= before.size() || field.offset >= after.size())
            continue;

        const size_t beforeSize = std::min(fieldSize, before.size() - field.offset);
        const size_t afterSize = std::min(fieldSize, after.size() - field.offset);
        const size_t compareSize = std::min(beforeSize, afterSize);
        if (compareSize == 0)
            continue;

        StructureFieldDiff diff;
        diff.name = field.name;
        diff.offset = field.offset;
        diff.size = compareSize;
        auto beforeStart = before.begin() + static_cast<std::vector<uint8_t>::difference_type>(field.offset);
        auto afterStart = after.begin() + static_cast<std::vector<uint8_t>::difference_type>(field.offset);
        diff.before.assign(beforeStart,
            beforeStart + static_cast<std::vector<uint8_t>::difference_type>(compareSize));
        diff.after.assign(afterStart,
            afterStart + static_cast<std::vector<uint8_t>::difference_type>(compareSize));
        diff.changed = std::memcmp(diff.before.data(), diff.after.data(), compareSize) != 0;
        diffs.push_back(std::move(diff));
    }
    return diffs;
}

} // namespace ce
