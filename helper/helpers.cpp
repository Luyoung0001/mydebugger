#include "../include/helpers.hpp"
#include <sstream>
namespace helper {
std::vector<std::string> split(const std::string &s, char delimiter) {
  std::vector<std::string> out{};
  std::stringstream ss{s};
  std::string item;

  while (std::getline(ss, item, delimiter)) {
    out.push_back(item);
  }

  return out;
}
bool is_prefix(const std::string &s, const std::string &of) {
  if (s.size() > of.size())
    return false;
  return std::equal(s.begin(), s.end(), of.begin());
}

} // namespace helper

namespace symmbol {
symmbol::symbol_type to_symbol_type(elf::stt sym) {
  switch (sym) {
  case elf::stt::notype:
    return symmbol::symbol_type::notype;
  case elf::stt::object:
    return symmbol::symbol_type::object;
  case elf::stt::func:
    return symmbol::symbol_type::func;
  case elf::stt::section:
    return symmbol::symbol_type::section;
  case elf::stt::file:
    return symmbol::symbol_type::file;
  default:
    return symmbol::symbol_type::notype;
  }
};
std::string to_string(symmbol::symbol_type st) {
  switch (st) {
  case symmbol::symbol_type::notype:
    return "notype";
  case symmbol::symbol_type::object:
    return "object";
  case symmbol::symbol_type::func:
    return "func";
  case symmbol::symbol_type::section:
    return "section";
  case symmbol::symbol_type::file:
    return "file";
  }
  return "null";
}
} // namespace sysmbol