#pragma once

#include "../include/breakpoint.hpp"
#include "../libelfin/dwarf/dwarf++.hh"
#include "../libelfin/elf/elf++.hh"
#include <string>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <unordered_map>

namespace debugger {
class Debugger {
  std::string m_prog_name;
  pid_t m_pid;
  std::unordered_map<std::intptr_t, breakpoint::BreakPoint>
      m_breakPoints; // 存储断点

  dwarf::dwarf m_dwarf;
  elf::elf m_elf;
  u_int64_t m_load_address; // elf 文件加载地址

public:
  // 这里不应该给默认参数，断言：传了正确的 prog_name，pid
  Debugger(std::string prog_name, pid_t pid);
  void run();
  void wait_for_signal();
  void initialise_load_address();
  u_int64_t offset_load_address(u_int64_t addr);

  // handlers
  void handl_command(const std::string &line);
  void continue_execution();

  void set_breakPoint(std::intptr_t addr);

  dwarf::die get_function_from_pc(u_int64_t pc);

  dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc);

  ~Debugger();
};

} // namespace debugger
