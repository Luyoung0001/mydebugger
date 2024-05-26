#ifndef DEBUGGER_HPP_
#define DEBUGGER_HPP_

#include "../ext/linenoise/linenoise.h"
#include "breakpoint.hpp"
#include "helpers.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <linux/types.h>
#include <string>
#include <sys/user.h>
#include <unordered_map>
#include <utility>
#include <iomanip>

enum class reg {
  rax,
  rbx,
  rcx,
  rdx,
  rdi,
  rsi,
  rbp,
  rsp,
  r8,
  r9,
  r10,
  r11,
  r12,
  r13,
  r14,
  r15,
  rip,
  rflags,
  cs,
  orig_rax,
  fs_base,
  gs_base,
  fs,
  gs,
  ss,
  ds,
  es

};

constexpr std::size_t n_registers = 27;

struct reg_descriptor {
  reg r;
  int dwarf_r;
  std::string name;
};

const std::array<reg_descriptor, n_registers> g_register_descriptors{{
    {reg::r15, 15, "r15"},
    {reg::r14, 14, "r14"},
    {reg::r13, 13, "r13"},
    {reg::r12, 12, "r12"},
    {reg::rbp, 6, "rbp"},
    {reg::rbx, 3, "rbx"},
    {reg::r11, 11, "r11"},
    {reg::r10, 10, "r10"},
    {reg::r9, 9, "r9"},
    {reg::r8, 8, "r8"},
    {reg::rax, 0, "rax"},
    {reg::rcx, 2, "rcx"},
    {reg::rdx, 1, "rdx"},
    {reg::rsi, 4, "rsi"},
    {reg::rdi, 5, "rdi"},
    {reg::orig_rax, -1, "orig_rax"},
    {reg::rip, -1, "rip"},
    {reg::cs, 51, "cs"},
    {reg::rflags, 49, "eflags"},
    {reg::rsp, 7, "rsp"},
    {reg::ss, 52, "ss"},
    {reg::fs_base, 58, "fs_base"},
    {reg::gs_base, 59, "gs_base"},
    {reg::ds, 53, "ds"},
    {reg::es, 50, "es"},
    {reg::fs, 54, "fs"},
    {reg::gs, 55, "gs"},
}};

uint64_t get_register_value(pid_t pid, reg r) {
  user_regs_struct regs;
  ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
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

class debugger {
  std::string m_prog_name;
  pid_t m_pid;
  std::unordered_map<std::intptr_t, BreakPoint> m_breakPoints; // 存储断点

public:
  // 这里不应该给默认参数，断言：传了正确的 prog_name，pid
  debugger(std::string prog_name, pid_t pid)
      : m_prog_name(prog_name), m_pid(pid) {}
  void run() {
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
  void handl_command(const std::string &line) {
    auto args = split(line, ' ');
    auto command = args[0];
    if (is_prefix(command, "continue")) {
      continue_execution();

    } else if (is_prefix(command, "break")) { // break 地址
      std::string addr{args[1], 2};
      this->set_breakPoint(std::stol(addr, 0, 16));

    } else if (is_prefix(command, "register")) {
      if (is_prefix(args[1], "dump")) {

        dump_registers();
      } else if (is_prefix(args[1], "read")) {

        std::cout << get_register_value(m_pid, get_register_from_name(args[2]))
                  << std::endl;
      } else if (is_prefix(args[1], "write")) {

        std::string val{args[3], 2}; // 假设是 0x 格式
        set_register_value(m_pid, get_register_from_name(args[2]),
                           std::stol(val, 0, 16));
      }

    } else if (is_prefix(command, "memory")) {
      std::string addr{args[2], 2}; // assume 0xADDRESS
      if (is_prefix(args[1], "read")) {

        std::cout << std::hex << read_memory(std::stol(addr, 0, 16))
                  << std::endl;
      } else if (is_prefix(args[1], "write")) {

        std::string val{args[3], 2}; // 假设是 0x
        write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
      }
    } else {
      std::cerr << "Unkown command\n";
    }
  }

  void continue_execution() {
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
  }

  void set_breakPoint(std::intptr_t addr) {
    std::cout << "Set breakpoint at address 0x" << std::hex << addr
              << std::endl;
    BreakPoint bp{m_pid, addr};
    bp.enable();
    m_breakPoints[addr] = bp;
  }

  void dump_registers() {
    for (const auto &rd : g_register_descriptors) {

      std::cout << rd.name << "0x" << std::setfill('0') << std::setw(16) << std::hex
                << get_register_value(m_pid, rd.r) << std::endl;
    }
  }

  void step_over_breakpoint() {
    auto possible_breakpoint_location =
        get_pc() - 1; // 拿到当前正在执行的指令地址,int3

    if (m_breakPoints.count(possible_breakpoint_location)) {
      auto &bp = m_breakPoints[possible_breakpoint_location]; // 得到断点
      if (bp.is_enabled()) {
        auto previous_instruction_address = possible_breakpoint_location;
        set_pc(previous_instruction_address); // 重新执行当前断点指令
        bp.disable();
        ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
        wait_for_signal();
        bp.enable();
      }
    }
  }
  void wait_for_signal() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
  }
  uint64_t read_memory(uint64_t address) {
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
  }

  void write_memory(uint64_t address, uint64_t value) {
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
  }

void set_pc(uint64_t pc) {
    set_register_value(m_pid, reg::rip, pc);
}

uint64_t get_pc() {
    return get_register_value(m_pid, reg::rip);
}


  ~debugger() {}
};

#endif