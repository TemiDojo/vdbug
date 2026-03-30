#include <memory>
#include "d_state.hh"

static bool handle_bp_hit(pid_t pid);
static void clear_breakpoint(pid_t pid, uintptr_t addr);
int ptrace_init(std::shared_ptr<DebuggerState> s);
static void err_check(void);
long ptrace_or_die(enum __ptrace_request op, pid_t pid, void *addr, void *data);
static bool single_step(pid_t pid);
static bool cont(pid_t pid);

