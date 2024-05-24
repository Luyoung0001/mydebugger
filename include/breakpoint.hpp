#ifndef BREAKPOINT_H_
#define BREAKPOINT_H_
#include <sys/cdefs.h>
#include <sys/types.h>
#include <cstdint>
#include <sys/ptrace.h>
#include <sys/wait.h>
class BreakPoint {
    pid_t m_pid;
    std::intptr_t m_addr;
    bool m_enabled;
    uint8_t m_saved_data; // 最低位的旧数据（1 字节）,之后需要恢复

  public:
    BreakPoint() {}
    BreakPoint(pid_t pid, std::intptr_t addr)
        : m_pid(pid), m_addr(addr), m_enabled(false), m_saved_data{} {}
    auto is_enabled() const -> bool { return m_enabled; }
    auto get_address() const -> std::intptr_t { return m_addr; }

    void enable() {
        auto data = ptrace(PT_READ_I, m_pid, reinterpret_cast<caddr_t>(m_addr), 0);
        m_saved_data =
            static_cast<uint8_t>(data & 0xff); // 拿到最低的一个字节（指令）
        uint64_t int3 = 0xcc;
        uint64_t data_with_int3 =
            ((data & ~0xff) | int3); // 得到被修改的最低的一个字节（指令）
        ptrace(PT_WRITE_I, m_pid, reinterpret_cast<caddr_t>(m_addr), data_with_int3); // 修改

        m_enabled = true;
    }
    void disable() {
        auto data = ptrace(PT_READ_I, m_pid, reinterpret_cast<caddr_t>(m_addr), 0);
        auto restored_data = ((data & ~0xff) | m_saved_data);
        ptrace(PT_WRITE_I, m_pid, reinterpret_cast<caddr_t>(m_addr), restored_data);
        m_enabled = false;
    }
};
#endif
