#pragma once
/// Utilities for structure dissector templates and C/C++ export.

#include "core/ct_file.hpp"

#include <optional>
#include <string>
#include <vector>

namespace ce {

struct StructureFieldDiff {
    std::string name;
    size_t offset = 0;
    size_t size = 0;
    bool changed = false;
    std::vector<uint8_t> before;
    std::vector<uint8_t> after;
};

bool saveStructureTemplate(const StructureDefinition& structure, const std::string& path);
std::optional<StructureDefinition> loadStructureTemplate(const std::string& path);
std::string generateCppStruct(const StructureDefinition& structure);
std::vector<StructureFieldDiff> compareStructureSnapshots(const StructureDefinition& structure,
    const std::vector<uint8_t>& before,
    const std::vector<uint8_t>& after);

} // namespace ce
