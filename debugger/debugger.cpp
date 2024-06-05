#include "../include/debugger.hpp"
#include "../include/helpers.hpp"
#include "../include/linenoise.h"
#include <fcntl.h>
#include <fstream>
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



void Debugger::run() {
  wait_for_signal();         // 刚启动等待子进程信号同步状态
  initialise_load_address(); // 初始化

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

  }

  else if (helper::is_prefix(command, "break")) { // break 地址
    std::string addr{args[1], 2};
    set_breakPoint(std::stol(addr, 0, 16));

  }

  else {
    std::cerr << "Unkown command\n";
  }
}

// 继续执行
void debugger::Debugger::continue_execution() {
  ptrace(PT_CONTINUE, m_pid, nullptr, 0);
  wait_for_signal();
}

// 打断点
void debugger::Debugger::set_breakPoint(std::intptr_t addr) {
  std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
  breakpoint::BreakPoint bp{m_pid, addr};
  bp.enable();
  m_breakPoints[addr] = bp;
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

debugger::Debugger::~Debugger() {}

} // namespace debugger