#pragma once
/// .CT Cheat Table format — XML-based save/load compatible with CE format.

#include "core/types.hpp"
#include <string>
#include <vector>

namespace ce {

struct CheatEntry {
    int id = 0;
    std::string description;
    uintptr_t address = 0;
    ValueType type = ValueType::Int32;
    std::string value;
    bool active = false;
    FreezeMode freezeMode = FreezeMode::Normal;
    std::string autoAsmScript;  // [ENABLE]/[DISABLE] script
    std::string luaScript;      // Lua code
    int parentId = -1;          // -1 = root level
    std::vector<int> childIds;
    bool isGroup = false;       // True = group header, no address
    std::string color;          // Hex color for display
    std::string dropdownList;   // Semicolon-separated choices
    std::string hotkeyKeys;     // Hotkey binding
};

struct StructureField {
    std::string name;
    size_t offset = 0;
    ValueType type = ValueType::Int32;
    size_t size = 4;
    std::string displayMethod;
    std::string nestedStructure;
};

struct StructureDefinition {
    std::string name;
    size_t size = 0;
    std::vector<StructureField> fields;
};

struct CheatTable {
    std::string gameName;
    std::string gameVersion;
    std::string author;
    std::string comment;
    std::string luaScript;      // Table-level Lua script
    std::vector<CheatEntry> entries;
    std::vector<StructureDefinition> structures;

    /// Save to .CT XML file.
    bool save(const std::string& path) const;

    /// Load from .CT XML file.
    bool load(const std::string& path);

    /// Save to JSON (our native format).
    bool saveJson(const std::string& path) const;

    /// Load from JSON.
    bool loadJson(const std::string& path);
};

} // namespace ce
