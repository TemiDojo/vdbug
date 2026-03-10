#include <sys/ptrace.h>

static void print_regs(struct user_regs_struct regs);
static void die(char *s);
static void err_check();
static int check_child_ret(pid_t tracee_pid);
static bool single_step(pid_t tracee_pid);
static bool next_i(pid_t tracee_pid);
static bool cont(pid_t tracee_pid);
static void display_info(pid_t tracee_pid);
static void d_regs(pid_t tracee_pid);
static void set_breakpoint(pid_t tracee_pid, void * address);
int stop_status(int status);
int ptrace_init(const char* target_path);
