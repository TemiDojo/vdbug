#pragma once
#include <sys/user.h>
#include <sys/ptrace.h>
#include <string>
#include <mutex>
#include <condition_variable>
#include "ftxui/component/screen_interactive.hpp"
extern "C" {
#include "../../dwarf/inc/dl_parser.h"
}

enum class DebugCommand {
    NONE,
    STEP,
    CONTINUE,
    NEXT,
    FINISH,
    KILL

};

struct DebuggerState {
    ftxui::ScreenInteractive* screen = nullptr;
    std::mutex d_mutex;
    std::condition_variable cv;
    std::string target_file;
    pid_t child_pid;
    uintptr_t initial_rsp;
    Matrix *m;
    struct user_regs_struct regs;
    DebugCommand current_cmd = DebugCommand::NONE;



};
