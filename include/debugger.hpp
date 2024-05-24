#ifndef DEBUGGER_HPP_
#define DEBUGGER_HPP_

#include "../ext/linenoise/linenoise.h"
#include "breakpoint.hpp"
#include <unordered_map>
#include "helpers.hpp"
#include <cstddef>
#include <iostream>
#include <string>

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
            set_breakPoint(std::stol(addr, 0, 16));

        }else {
            std::cerr << "Unkown command\n";
        }
    }
    void continue_execution() {
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
}

    void set_breakPoint(std::intptr_t addr) {
        std::cout << "Set breakpoint at address 0x" << std::hex << addr
                  << std::endl;
        BreakPoint bp{m_pid, addr};
        bp.enable();
        m_breakPoints[addr] = bp;
    }

    ~debugger() {}
};

#endif