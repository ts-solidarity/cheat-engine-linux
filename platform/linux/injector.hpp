#pragma once
/// Inject a shared library (.so) into a running process via ptrace + dlopen.

#include "platform/process_api.hpp"
#include "symbols/elf_symbols.hpp"
#include <string>
#include <expected>

namespace ce::os {

/// Inject a .so file into a target process.
/// Returns the handle returned by dlopen, or an error string.
std::expected<uintptr_t, std::string>
injectLibrary(ProcessHandle& proc, SymbolResolver& resolver, const std::string& soPath);

} // namespace ce::os
