#pragma once
/// Utilities for structure dissector templates and C/C++ export.

#include "core/ct_file.hpp"

#include <optional>
#include <string>

namespace ce {

bool saveStructureTemplate(const StructureDefinition& structure, const std::string& path);
std::optional<StructureDefinition> loadStructureTemplate(const std::string& path);
std::string generateCppStruct(const StructureDefinition& structure);

} // namespace ce
