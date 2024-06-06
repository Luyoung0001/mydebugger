#include "../include/debugger.hpp"
#include "../include/helpers.hpp"
#include "../include/linenoise.h"
#include "../include/registers.hpp"
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <sys/cdefs.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_map>

namespace debugger {

// 这里不应该给默认参数，断言：传了正确的 prog_name，pid
Debugger::Debugger(std::string prog_name, pid_t pid)
    : m_prog_name(prog_name), m_pid(pid) {

  auto fd = open(m_prog_name.c_str(), O_RDONLY); // 打开文件

  m_elf = elf::elf{elf::create_mmap_loader(fd)};            // elf 文件
  m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)}; // dwarf
}

// 等待信号
void Debugger::wait_for_signal() {
  int wait_status;
  auto options = 0;
  waitpid(m_pid, &wait_status, options);

  // 等待子进程发来的信号似乎不够，可以顺便获得上次debug 发送给子进程的信息
  auto siginfo = get_signal_info();

  // 根据 siginfo_t signo 来 判断
  switch (siginfo.si_signo) {
  case SIGTRAP:
    handle_sigtrap(siginfo);
    break;
  case SIGSEGV:
    std::cout << "segfalt, reason: " << siginfo.si_code << std::endl;
    break;
  default:
    std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
  }
}

// 处理 trap
// 当 debug 进程向被跟踪的进程通过 ptrace()
// 发送了一个信号之后，首先等待，这是同步；
// 之后要对一类重要的信号进行再处理，这就是 SIGTRAP 信号；
// SIGTRAP 信号一般是由
// 断点、单步执行、异常和错误引起的，因此这里要分别处理这几种情况
void Debugger::handle_sigtrap(siginfo_t info) {
  switch (info.si_code) {
  case SI_KERNEL:
  // 这是重点要处理的信号源,断点引起的
  case TRAP_BRKPT: {
    set_pc(get_pc() - 1);
    std::cout << "Hit breakpoint at adsress 0x" << std::hex << get_pc()
              << std::endl;
    auto offset_pc = offset_load_address(get_pc()); // 获取当前pc 的 offset
    auto line_entry =
        get_line_entry_from_pc(offset_pc); // 从 offset 返回 line_table 迭代器

    print_source(line_entry->file->path, line_entry->line); // 打印源代码
    return;
  }
  case TRAP_TRACE:
    return;
  default:
    // 我们只关心前两种信号源
    std::cout << "unknown SIGTRAP code " << info.si_code << std::endl;
  }
}

// 初始化:获取elf加载地址
void Debugger::initialise_load_address() {
  if (m_elf.get_hdr().type == elf::et::dyn) {
    // 在这个系统文件中找到加载地址
    std::ifstream map("/proc/" + std::to_string(m_pid) + "/maps");
    std::string addr;
    std::getline(map, addr, '-');

    m_load_address = std::stoull(addr, 0, 16);
  }
}

// 获取加载地址的偏移量，因为 die 中记录偏移量
u_int64_t Debugger::offset_load_address(u_int64_t addr) {
  return addr - m_load_address;
}

// 打印源码
void Debugger::print_source(const std::string &file_name, unsigned line,
                            unsigned n_lines_context) {
  std::ifstream file{file_name};

  std::cout << "OK, it is here. " << std::endl;

  // 调整开始的行和结束的行
  auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
  auto end_line = line + n_lines_context +
                  (line < n_lines_context ? n_lines_context - line : 0) + 1;

  char c{};
  auto current_line = 1u;
  // 跳到我们要打印的开始行
  while (current_line != start_line && file.get(c)) {
    if (c == '\n') {
      ++current_line;
    }
  }

  std::cout << (current_line == line ? "> " : "  ");

  // 输出
  while (current_line <= end_line && file.get(c)) {
    std::cout << c;
    if (c == '\n') {
      ++current_line;
      // Output cursor if we're at the current line
      std::cout << (current_line == line ? "> " : "  ");
    }
  }

  // 刷新以及换行
  std::cout << std::endl;
}

// 获取最后一次发送的信号信息,siginfo_f 如以下结构
// siginfo_t {
//     int      si_signo;     /* Signal number */
//     int      si_errno;     /* An errno value */
//     int      si_code;      /* Signal code */
//     int      si_trapno;    /* Trap number that caused
//                               hardware-generated signal
//                               (unused on most architectures) */
//     pid_t    si_pid;       /* Sending process ID */
//     ....}

siginfo_t Debugger::get_signal_info() {
  siginfo_t info;
  ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
  return info;
}

void Debugger::run() {
  wait_for_signal();         // 刚启动等待子进程信号同步状态
  initialise_load_address(); // 初始化

  char *line = nullptr;
  while ((line = linenoise("minidbg> ")) != nullptr) {
    handle_command(line);
    linenoiseHistoryAdd(line);
    linenoiseFree(line);
  }
}

// handlers
void Debugger::handle_command(const std::string &line) {
  auto args = helper::split(line, ' ');
  auto command = args[0];
  if (helper::is_prefix(command, "continue")) {
    continue_execution();

  }

  // 打断点
  else if (helper::is_prefix(command, "break")) { // break 地址
    std::string addr{args[1], 2};
    set_breakPoint(std::stol(addr, 0, 16));

  }

  // 读写内存
  else if (helper::is_prefix(command, "memory")) {
    std::string addr{args[2], 2}; // assume 0xADDRESS

    if (helper::is_prefix(args[1], "read")) {
      std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
    }
    if (helper::is_prefix(args[1], "write")) {
      std::string val{args[3], 2}; // assume 0xVAL
      write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
    }
  }

  // 读写寄存器
  else if (helper::is_prefix(command, "register")) {
    if (helper::is_prefix(args[1], "dump")) {
      dump_registers();
    } else if (helper::is_prefix(args[1], "read")) {
      std::cout << get_register_value(
                       m_pid, registers::get_register_from_name(args[2]))
                << std::endl;
    } else if (helper::is_prefix(args[1], "write")) {
      std::string val{args[3], 2}; // assume 0xVAL
      set_register_value(m_pid, registers::get_register_from_name(args[2]),
                         std::stol(val, 0, 16));
    }
  }

  // 单步执行，汇编指令级的
  else if (helper::is_prefix(command, "stepi")) {
    single_step_instruction_with_breakpoint_check();
    auto line_entry = get_line_entry_from_pc(get_pc());
    // 打印源代码 context
    print_source(line_entry->file->path, line_entry->line);

  }

  else {
    std::cerr << "Unkown command\n";
  }
}

// 继续执行
void Debugger::continue_execution() {
  step_over_breakpoint();
  ptrace(PT_CONTINUE, m_pid, nullptr, 0);
  wait_for_signal();
}

// 单步执行
void Debugger::single_step_instruction() {
  ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
}

// 单步执行 with bp
void Debugger::single_step_instruction_with_breakpoint_check() {
  // 如果即将执行的指令是一个断点，那么就跳过
  if (m_breakPoints.count(get_pc())) {
    step_over_breakpoint();
  } else {
    single_step_instruction();
  }
}

// 跳过断点
void Debugger::step_over_breakpoint() {
  // 二次检查
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

// 打断点
void Debugger::set_breakPoint(std::intptr_t addr) {
  std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
  breakpoint::BreakPoint bp{m_pid, addr};
  bp.enable();
  m_breakPoints[addr] = bp;
}

// step_out
void Debugger::step_out() {
  // 获取当前函数的函数栈帧，它存在 rbp 寄存器中
  auto frame_pointer =
      registers::get_register_value(m_pid, registers::reg::rbp);
  // 一般返回地址的值位于栈帧存储位置的上面（栈向下、地址减小的方向增涨）,uint64_t
  // 是单位，因此是 8 个字节
  auto return_address = read_memory(frame_pointer + 8);

  // 标记是否返回后移除这个断点，因为这个断点是为了返回停在那里才产生的，因此我们必须将它移除掉
  bool should_remove_breakpoint = false;

  // 如果返回地址不是一个断点，那么在此打断点，以便于返回后暂停在那里
  if (!m_breakPoints.count(return_address)) {
    set_breakPoint(return_address);
    should_remove_breakpoint = true;
  }
  continue_execution();
  if (should_remove_breakpoint) {
    remove_breakpoint(return_address);
  }
}

// 移除断点
void Debugger::remove_breakpoint(uint64_t addr) {
  if (m_breakPoints.count(addr)) {
    auto &bp = m_breakPoints[addr];
    bp.disable();
  }
  m_breakPoints.erase(addr);
}

// step_in
void Debugger::step_in() {
  // 拿到 line entry 的行编号
  auto line = get_line_entry_from_pc(get_offset_pc())->line;

  while (get_line_entry_from_pc(get_offset_pc())->line == line) {
    // 一直执行，直到进入一个新的 line entry，此时它的行号就会变化
    single_step_instruction_with_breakpoint_check();
  }
  // 打印新的函数内部的函数
  auto line_entry = get_line_entry_from_pc(get_offset_pc());
  print_source(line_entry->file->path, line_entry->line);
}

uint64_t Debugger::get_offset_pc() { return offset_load_address(get_pc()); }

// step_over
// 有很多的方法，不过目前来说最简单的方法是给当前函数的每一个行打一个断点，然后
// continue
uint64_t Debugger::offset_dwarf_address(uint64_t addr) {
  return addr + m_load_address;
}
void Debugger::step_over() {
  auto func = get_function_from_pc(get_offset_pc());
  auto func_entry = at_low_pc(func);
  auto func_end = dwarf::at_high_pc(func);

  // 得到函数入口的 line entry
  auto line = get_line_entry_from_pc(func_entry);

  // 得到当前 指令 的 line entry
  auto start_line = get_line_entry_from_pc(get_offset_pc());

  std::vector<std::intptr_t> to_delete;
  
  while (line->address < func_end) {
    auto load_adress = offset_load_address(line->address);
    if (line->address != start_line->address &&
        !m_breakPoints.count(load_adress)) {
      set_breakPoint(load_adress);
      to_delete.push_back(load_adress);
    }
    ++line;
  }
  // 移除这些断点
  auto frame_pointer =
      registers::get_register_value(m_pid, registers::reg::rbp);
  auto return_address = read_memory(frame_pointer + 8);

  if (!m_breakPoints.count(return_address)) {
    set_breakPoint(return_address);
    to_delete.push_back(return_address);
  }
  continue_execution();
  for (auto addr : to_delete) {
    remove_breakpoint(addr);
  }
}

// dwarf 文件信息处理

// 从 pc 判断位于哪一个函数中
dwarf::die Debugger::get_function_from_pc(u_int64_t pc) {
  for (auto &cu : m_dwarf.compilation_units()) { // 循环遍历所有cu
    if (die_pc_range(cu.root()).contains(pc)) {
      for (const auto &die :
           cu.root()) { // 在符合条件的 cu 中 遍历 DWARF Information
                        // Entry，其中 cu.root() 返回它的 root
                        // die.类似于如下结构中遍历每一个 die：
                        //       .debug_info

        // COMPILE_UNIT<header overall offset = 0x00000000>:
        // < 0><0x0000000b>  DW_TAG_compile_unit
        //                     DW_AT_producer              clang version 3.9.1
        //                     (tags/RELEASE_391/final) DW_AT_language
        //                     DW_LANG_C_plus_plus DW_AT_name
        //                     /path/to/variable.cpp DW_AT_stmt_list 0x00000000
        //                     DW_AT_comp_dir              /path/to
        //                     DW_AT_low_pc                0x00400670
        //                     DW_AT_high_pc               0x0040069c

        // LOCAL_SYMBOLS:
        // < 1><0x0000002e>    DW_TAG_subprogram
        //                       DW_AT_low_pc                0x00400670
        //                       DW_AT_high_pc               0x0040069c
        //                       DW_AT_frame_base            DW_OP_reg6
        //                       DW_AT_name                  main
        //                       DW_AT_decl_file             0x00000001
        //                       /path/to/variable.cpp DW_AT_decl_line
        //                       0x00000001 DW_AT_type <0x00000077>
        //                       DW_AT_external              yes(1)
        // < 2><0x0000004c>      DW_TAG_variable
        //                         DW_AT_location              DW_OP_fbreg -8
        // ...

        if (die.tag ==
            dwarf::DW_TAG::subprogram) { // 如果 tag 是一个函数，那么就判断这个
                                         // die 是否包含这个 pc
          if (die_pc_range(die).contains(pc)) {
            return die;
          }
        }
      }
    }
  }
  throw std::out_of_range{"Cannot find function"};
}

// 从 pc 得到 line_table 的迭代器
dwarf::line_table::iterator Debugger::get_line_entry_from_pc(uint64_t pc) {
  for (auto &cu : m_dwarf.compilation_units()) { // 遍历所有 cu
    if (die_pc_range(cu.root()).contains(pc)) {
      auto &lt = cu.get_line_table(); // 拿到 cu 的line table，line table
                                      // 类似于以下结构
      // <pc>        [lno,col] NS BB ET PE EB IS= DI= uri: "filepath"
      // 0x00400670  [   1, 0] NS uri: "/path/to/test.cpp"
      // 0x00400676  [   2,10] NS PE
      // 0x0040067e  [   3,10] NS
      // 0x00400686  [   4,14] NS
      // 0x0040068a  [   4,16]
      // 0x0040068e  [   4,10]
      // 0x00400692  [   5, 7] NS
      // 0x0040069a  [   6, 1] NS
      // 0x0040069c  [   6, 1] NS ET

      auto it = lt.find_address(pc);
      if (it == lt.end()) {
        throw std::out_of_range{"Cannot find line entry"};
      } else {
        return it;
      }
    }
  }
  // 并没有找到 line table的时候 抛异常
  throw std::out_of_range{"Cannot find line entry"};
}

// 关于 pc 的 一些函数
uint64_t Debugger::get_pc() {
  // 从 rip 中或得 pc
  return registers::get_register_value(m_pid, registers::reg::rip);
}

void Debugger::set_pc(uint64_t pc) {
  // 直接修改 rip 为 pc
  set_register_value(m_pid, registers::reg::rip, pc);
}

// 读写信息
// 输出寄存器的信息
void Debugger::dump_registers() {
  for (const auto &rd : registers::g_register_descriptors) {
    std::cout << rd.name << " 0x" << std::setfill('0') << std::setw(16)
              << std::hex << get_register_value(m_pid, rd.r) << std::endl;
  }
}
uint64_t Debugger::read_memory(uint64_t address) {
  return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void Debugger::write_memory(uint64_t address, uint64_t value) {
  ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

Debugger::~Debugger() {}

} // namespace debugger