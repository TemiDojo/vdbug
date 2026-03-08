#include <sys/ptrace.h>

static void print_regs(struct user_regs_struct regs);
int stop_status(int status);
int ptrace_init(const char* target_path);
