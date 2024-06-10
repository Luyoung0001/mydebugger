#pragma once
#include "../libelfin/elf/elf++.hh"
#include <string>
#include <vector>

namespace helper {
std::vector<std::string> split(const std::string &s, char delimiter);
bool is_prefix(const std::string &s, const std::string &of);

} // namespace helper

namespace symmbol {
enum class symbol_type {
  notype,  // No type (e.g., absolute symbol)
  object,  // Data object
  func,    // Function entry point
  section, // Symbol is associated with a section
  file,    // Source file associated with the
};         // object file

struct symbol {
  symbol_type type;
  std::string name;
  std::uintptr_t addr;
};

std::string to_string(symbol_type st);
symbol_type to_symbol_type(elf::stt sym);
} // namespace symbol