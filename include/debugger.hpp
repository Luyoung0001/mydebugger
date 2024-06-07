#pragma once

#include "../libelfin/dwarf/dwarf++.hh"
#include "../libelfin/elf/elf++.hh"
#include "breakpoint.hpp"
#include <csignal>
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
  std::intptr_t m_load_address; // elf 文件加载地址

public:
  // 这里不应该给默认参数，断言：传了正确的 prog_name，pid
  Debugger(std::string prog_name, pid_t pid);
  void run();
  void wait_for_signal();
  void initialise_load_address();
  std::intptr_t offset_load_address(std::intptr_t addr);
  void print_source(const std::string &file_name, unsigned line,
                    unsigned n_lines_context = 5u);
  siginfo_t get_signal_info();
  void handle_sigtrap(siginfo_t siginfo);

  // pc
  std::intptr_t get_pc();
  void set_pc(std::intptr_t pc);

  // read & write
  void dump_registers();
  uint64_t read_memory(std::intptr_t address);
  void write_memory(std::intptr_t address, uint64_t value);

  // handlers
  void handle_command(const std::string &line);
  void continue_execution();

  void set_breakPoint(std::intptr_t addr);
  void step_over_breakpoint();
  void single_step_instruction();
  void single_step_instruction_with_breakpoint_check();
  void step_out();
  void step_in();
  void step_over();
  void remove_breakpoint(std::intptr_t addr);
  std::intptr_t get_offset_pc();
  std::intptr_t offset_dwarf_address(std::intptr_t addr);

  dwarf::die get_function_from_pc(std::intptr_t pc);

  dwarf::line_table::iterator get_line_entry_from_pc(std::intptr_t pc);

  ~Debugger();
};

} // namespace debugger
