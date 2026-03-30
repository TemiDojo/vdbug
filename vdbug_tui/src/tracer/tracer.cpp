#include <memory>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include "../inc/d_state.hh"

#define MAX_BREAKPOINTS 16

typedef struct {
    uintptr_t addr;
    uint8_t orig_byte;
    bool active;
} Breakpoint;

static Breakpoint bptable[MAX_BREAKPOINTS];


unsigned long base = 0;


__attribute__((noreturn)) static void die(char *s) {
    puts(s);
    exit(EXIT_FAILURE);
} 

static void err_check(void) {
    switch(errno) {
        case EBUSY: die("ptrace: EBUSY");
        case EFAULT: die("ptrace: EFAULT");
        case EINVAL: die("ptrace: EINVLA");
        case EIO: die("ptrace: EIO");
        case EPERM: die("ptrace: EPERM");
        case ESRCH: //die("ptrace: ESRCH");
        default: return;
    }
}

static long ptrace_or_die(enum __ptrace_request op, pid_t pid, void *addr, void *data) {
    long result = ptrace(op, pid, addr, data);
    if (result == -1){
        err_check();
    }
    return result;
}

long update_regs(std::shared_ptr<DebuggerState> s, pid_t pid) {
    return ptrace_or_die(PTRACE_GETREGS, pid, NULL, &s->regs);
}

static int check_child_ret(pid_t pid) {
    int wstatus;
    if (waitpid(pid, &wstatus, 0) != pid)
        die("waitpid failed");
    return wstatus;
}

static bool single_step(pid_t pid) {
    long ret = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    int wstatus = check_child_ret(pid);
    
    if (ret == -1)
        err_check();
    if (WIFEXITED(wstatus)) {
        //puts("Tracee exited.");
        return false;
    }
    if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP)
        //puts("Tracee stopped.");
        //continue;

    return true;
}

static void clear_breakpoint(pid_t pid, uintptr_t addr) {
    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        if (bptable[i].active && bptable[i].addr == addr) {
            unsigned long word = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
            ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)((word & ~0xFFUL) | bptable[i].orig_byte));
            bptable[i].active = false;
            return;
        }
    }
}

static bool handle_bp_hit(pid_t pid) {
    struct user_regs_struct regs = {};
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    uintptr_t bp_addr = regs.rip - 1;

    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        if (bptable[i].active && bptable[i].addr == bp_addr) {
            clear_breakpoint(pid, bp_addr);
            regs.rip = bp_addr;
            ptrace(PTRACE_SETREGS, pid, NULL, &regs);
            return true;
        }
    }
    return false;
}



static bool cont(pid_t pid) {
    long ret = ptrace(PTRACE_CONT, pid, NULL, NULL);
    int wstatus = check_child_ret(pid);
    
    if (ret == -1)
        err_check();
    if (WIFEXITED(wstatus)) {
        //puts("Tracee exited.");
        return false;
    }
    if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP)
        handle_bp_hit(pid);
        //puts("Tracee stopped.");
        //continue;

    return true;
}



int get_base_address(pid_t pid) {
    char path[256];
    sprintf(path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        return -1;
    }

    fscanf(f, "%lx", &base);
    fclose(f);
    return 1;
}

static void set_breakpoint(pid_t pid, void *address) {
    uintptr_t addr = (uintptr_t)address;

    for (int i = 0; i < MAX_BREAKPOINTS; i++)
        if (bptable[i].active && bptable[i].addr == addr)
            return;

    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        if (!bptable[i].active) {
            unsigned long word = ptrace(PTRACE_PEEKDATA, pid, address, NULL);
            bptable[i].addr      = addr;
            bptable[i].orig_byte = word & 0xFF;
            bptable[i].active    = true;
            ptrace(PTRACE_POKEDATA, pid, address, (void *)((word & ~0xFFUL) | 0xCC));
            return;
        }
    }
    puts("too many breakpoints");
}



int ptrace_init(std::shared_ptr<DebuggerState> s) {

    pid_t tracee_pid = fork();

    if (tracee_pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(s->target_file.c_str(), s->target_file.c_str(), NULL);
        die("execl failed");
    }
    s->child_pid = tracee_pid;

    int status;
    waitpid(tracee_pid, &status, 0);
    if (WIFSTOPPED(status)) {

    }

    std::unique_lock<std::mutex> lock(s->d_mutex);
    update_regs(s, tracee_pid);
    lock.unlock();
    unsigned long offset = s->m->arr[0]->address;
    s->screen->PostEvent(ftxui::Event::Custom);
    get_base_address(tracee_pid);

    if (base != 0) {
        set_breakpoint(tracee_pid, (void *)(base + offset));
    }

    while(1) {
        std::unique_lock<std::mutex> lock(s->d_mutex);
        s->cv.wait(lock, [&]{return s->current_cmd != DebugCommand::NONE; });
        DebugCommand cmd = s->current_cmd;

        if (cmd == DebugCommand::KILL) {
            ptrace(PTRACE_KILL, s->child_pid, nullptr, nullptr);
            return 1;
        } else if (cmd == DebugCommand::STEP) {
            single_step(tracee_pid);
            update_regs(s, tracee_pid);
        } else if (cmd == DebugCommand::CONTINUE) {
            cont(tracee_pid);
            update_regs(s, tracee_pid);
        }

        s->current_cmd = DebugCommand::NONE;

        lock.unlock();
        s->screen->PostEvent(ftxui::Event::Custom);

    }

    return 0;


}




