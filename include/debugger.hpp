#ifndef DEBUGGER_HPP_
#define DEBUGGER_HPP_

#include "../ext/libelfin/dwarf/dwarf++.hh"
#include "../ext/libelfin/elf/elf++.hh"
#include "../ext/linenoise/linenoise.h"
#include "breakpoint.hpp"
#include "helpers.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h> // 对于 open 和 O_RDONLY
#include <fstream>
#include <iomanip>
#include <iostream>
#include <linux/types.h>
#include <string>
#include <sys/user.h>
#include <unordered_map>
#include <utility>

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
  dwarf::dwarf m_dwarf;
  elf::elf m_elf;
  uint64_t m_load_address;
  std::unordered_map<std::intptr_t, BreakPoint> m_breakPoints; // 存储断点

public:
  // 这里不应该给默认参数，断言：传了正确的 prog_name，pid
  debugger(std::string prog_name, pid_t pid)
      : m_prog_name{std::move(prog_name)}, m_pid{pid} {
    auto fd = open(m_prog_name.c_str(), O_RDONLY);

    m_elf = elf::elf{elf::create_mmap_loader(fd)};            //
    m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)}; //
  }
  void run() {
    wait_for_signal();
    initialise_load_address(); // load stack frame

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

      std::cout << rd.name << ": 0x" << std::setfill('0') << std::setw(16)
                << std::hex << get_register_value(m_pid, rd.r) << std::endl;
    }
  }

  void wait_for_signal() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);

    auto siginfo = get_signal_info();

    switch (siginfo.si_signo) {
    case SIGTRAP:
      handle_sigtrap(siginfo);
      break;
    case SIGSEGV:
      std::cout << "Segfalt. Reason: " << siginfo.si_code << std::endl;
      break;
    default:
      std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
    }
  }
  // handlers
  void handle_sigtrap(siginfo_t info) {
    switch (info.si_code) {
    // 断点
    case SI_KERNEL:
    case TRAP_BRKPT: {
      set_pc(get_pc() - 1); // 即将重新执行当前指令
      std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc()
                << std::endl;
      auto offset_pc = offset_load_address(get_pc()); // 拿到当前 pc 的相对地址

      auto line_entry = get_line_entry_from_pc(offset_pc);
      print_source(line_entry->file->path, line_entry->line, 5u);
      return;
    }
    // 单步执行
    case TRAP_TRACE:
      return;
    default:
      std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
      return;
    }
  }
  void step_over_breakpoint() {
    if (m_breakPoints.count(get_pc())) {
      auto &bp = m_breakPoints[get_pc()];
      if (bp.is_enabled()) {
        bp.disable();
        ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
        wait_for_signal();
        bp.enable();
      }
    }
  }
  uint64_t read_memory(uint64_t address) {
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
  }

  void write_memory(uint64_t address, uint64_t value) {
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
  }

  void set_pc(uint64_t pc) { set_register_value(m_pid, reg::rip, pc); }

  uint64_t get_pc() { return get_register_value(m_pid, reg::rip); }

  dwarf::die get_function_from_pc(uint64_t pc) {
    for (auto &cu :
         m_dwarf.compilation_units()) { // 在编译单元中遍历编译单元 cu
      if (dwarf::die_pc_range(cu.root()).contains(
              pc)) {                        // 如果某个 cu 中包含 pc
        for (const auto &die : cu.root()) { // 然后在 cu 中遍历每一个 die
          if (dwarf::die_pc_range(die).contains(pc)) {
            return die;
          }
        }
      }
    }
    throw std::out_of_range{"Cannot find function"};
  }

  dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
      if (dwarf::die_pc_range(cu.root()).contains(pc)) {
        auto &lt = cu.get_line_table();
        auto it = lt.find_address(pc);
        if (it == lt.end()) {
          throw std::out_of_range{"Cannot find line entry"};
        } else {
          return it;
        }
      }
    }
    throw std::out_of_range{"Cannot find line entry"};
  }
  void initialise_load_address() {
    if (m_elf.get_hdr().type == elf::et::dyn) {
      std::ifstream map("/proc" + std::to_string(m_pid) +
                        "/maps"); // 在 maps中查找 load address
      std::string addr;
      std::getline(
          map, addr,
          '-'); // 比如：5641dcfbd000-5641dcfbe000 r--p 00000000 00:01 13647
      m_load_address = std::stoi(addr, 0, 16);
    }
  }
  uint64_t offset_load_address(uint64_t addr) { return addr - m_load_address; }

  // file_name：要读取的文件名。
  // line：关注的中心行号。
  // n_lines_context：在中心行号周围需要打印的行的数量。
  void print_source(const std::string &file_name, unsigned line,
                    unsigned n_lines_context) {
    std::ifstream file{file_name};

    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context +
                    (line < n_lines_context ? n_lines_context - line : 0) + 1;

    char c{};
    auto current_line = 1u;

    // 跳到开始的行
    while (current_line != start_line && file.get(c)) {
      if (c != '\n') {
        ++current_line;
      }
    }
    // 输出指针，如果我们在当前行
    std::cout << (current_line == line ? "> " : " ");

    // 打印行
    while (current_line <= end_line && file.get(c)) {
      std::cout << c;
      if (c == '\n') {
        ++current_line;
        // 也同样输出当前行的指针
        std::cout << (current_line == line ? "> " : " ");
      }
    }
    std::cout << std ::endl; // 刷新且换行
  }

  // 得到发送到 被跟踪进程 最后一个信号
  siginfo_t get_signal_info() {
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
    return info;
  }

  ~debugger() {}
};

#endif