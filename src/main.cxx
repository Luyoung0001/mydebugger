#include "../include/debugger.hpp"
#include <cstddef>
#include <iostream>
#include <unistd.h>
int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Program paras are not right.";
        return -1;
    }
    auto proj = argv[1];
    auto pid = fork();
    if (pid == 0) {
        // child progress
        // debugged progress
        ptrace(PT_TRACE_ME,0,nullptr,0);
        execl(proj,proj,nullptr);
    } else if (pid >= 1) {
        // parent progress
        // debugger progress

        std::cout << "Start debugging the progress: " << proj
                  << ", pid = " << pid << ":\n";
        debugger dbg(proj, pid);
        dbg.run();
    }

    return 0;
}