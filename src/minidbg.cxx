#include <sys/personality.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <iostream>
#include "../include/debugger.hpp"

void execute_debugee(const std::string& prog_name) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        std::cerr << "Error in ptrace\n";
        return;
    }
    execl(prog_name.c_str(), prog_name.c_str(), nullptr);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Program paras are not right.";
        return -1;
    }

    auto proj = argv[1];
    auto pid = fork();
    if (pid == 0) {
        personality(ADDR_NO_RANDOMIZE);  // 调试模式
        execute_debugee(proj);
    } else if (pid >= 1) {
        std::cout << "Start debugging the progress: " << proj
                  << ", pid = " << pid << ":\n";
        debugger::Debugger dbg(proj, pid);
        dbg.run();
    }

    return 0;
}