#pragma once
#include <cstdint>
#include <sys/cdefs.h>
#include <sys/types.h>

namespace breakpoint {
class BreakPoint {
  pid_t m_pid;
  std::intptr_t m_addr;
  bool m_enabled;
  uint8_t m_saved_data; // 最低位的旧数据（1 字节）,之后需要恢复

public:
  BreakPoint();
  BreakPoint(pid_t pid, std::intptr_t addr);
  auto is_enabled() const -> bool;
  auto get_address() const -> std::intptr_t;

  void enable();
  void disable();
};

} // namespace breakpoint
