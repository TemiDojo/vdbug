#pragma once
#include <sys/user.h>
#include <sys/ptrace.h>

struct DebuggerState {

    struct user_regs_struct regs;


};
