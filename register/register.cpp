#include "../libelfin/dwarf/dwarf++.hh"
#include "../libelfin/elf/elf++.hh"
#include "../include/linenoise.h"
#include "../include/breakpoint.hpp"
#include "../include/helpers.hpp"
#include "../include/registers.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h> // 对于 open 和 O_RDONLY
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unordered_map>
#include <utility>

namespace registers {

uint64_t get_register_value(pid_t pid, reg r) {
  user_regs_struct regs;
  ptrace(PT_GETREGS, pid, nullptr, &regs);
  auto it =
      std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                   [r](auto &&rd) { return rd.r == r; });
  return *(reinterpret_cast<uint64_t *>(&regs) +
           (it - begin(g_register_descriptors)));
}

void set_register_value(pid_t pid, reg r, uint64_t value) {
  user_regs_struct regs;
  ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
  auto it =
      std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                   [r](auto &&rd) { return rd.r == r; });
  *(reinterpret_cast<int64_t *>(&regs) + (it - begin(g_register_descriptors))) =
      value;
  ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}

uint64_t get_register_value_from_dwarf_register(pid_t pid, unsigned regnum) {
  auto it =
      std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                   [regnum](auto &&rd) { return rd.dwarf_r == regnum; });
  if (it == end(g_register_descriptors)) {
    throw std::out_of_range{"Unknown dwarf register"};
  }
  return get_register_value(pid, it->r);
}

std::string get_register_name(reg r) {
  auto it =
      std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                   [r](auto &&rd) { return rd.r == r; });
  return it->name;
}

reg get_register_from_name(const std::string &name) {
  auto it =
      std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                   [name](auto &&rd) { return rd.name == name; });
  return it->r;
}

} // namespace registers