#pragma once

#include "../include/breakpoint.hpp"
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

public:
  // 这里不应该给默认参数，断言：传了正确的 prog_name，pid
  Debugger(std::string prog_name, pid_t pid);
  void run();

  // handlers
  void handl_command(const std::string &line);
  void continue_execution();

  void set_breakPoint(std::intptr_t addr);

  ~Debugger();
};

} // namespace debugger
