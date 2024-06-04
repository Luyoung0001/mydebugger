#include "../include/debugger.hpp"
#include "../include/linenoise.h"
#include "../include/helpers.hpp"
#include <iostream>
#include <string>
#include <sys/cdefs.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unordered_map>

namespace debugger {

// 这里不应该给默认参数，断言：传了正确的 prog_name，pid
Debugger::Debugger(std::string prog_name, pid_t pid)
    : m_prog_name(prog_name), m_pid(pid) {}

void Debugger::run() {
  int wait_status;
  auto options = 0;
  waitpid(m_pid, &wait_status, options);
  char *line = nullptr;
  while ((line = linenoise("minidbg> ")) != nullptr) {
    handl_command(line);
    linenoiseHistoryAdd(line);
    linenoiseFree(line);
  }
}

// handlers
void Debugger::handl_command(const std::string &line) {
  auto args = helper::split(line, ' ');
  auto command = args[0];
  if (helper::is_prefix(command, "continue")) {
    continue_execution();

  } else if (helper::is_prefix(command, "break")) { // break 地址
    std::string addr{args[1], 2};
    set_breakPoint(std::stol(addr, 0, 16));

  } else {
    std::cerr << "Unkown command\n";
  }
}
void debugger::Debugger::continue_execution() {
  ptrace(PT_CONTINUE, m_pid, nullptr, 0);
  int wait_status;
  auto options = 0;
  waitpid(m_pid, &wait_status, options);
}

void debugger::Debugger::set_breakPoint(std::intptr_t addr) {
  std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
  breakpoint::BreakPoint bp{m_pid, addr};
  bp.enable();
  m_breakPoints[addr] = bp;
}

debugger::Debugger::~Debugger() {}

} // namespace debugger