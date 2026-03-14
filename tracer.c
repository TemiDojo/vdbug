#include <elf.h>        // for Elf64_Shdr, Elf64_Section
#include <fcntl.h>      // for open, O_RDONLY
#include <gelf.h>       // for GElf_Sym, gelf_getsym
#include <libelf.h>     // for elf_version, elf_begin, elf_getscn, elf_nextscn
#include <limits.h>     // for CHAR_BIT
#include <signal.h>     // for SIG*
#include <stdint.h>     // for uint*_t
#include <stdio.h>      // for puts, printf, getline
#include <stdlib.h>     // for exit, EXIT_FAILURE, NULL
#include <string.h>     // for memcpy
#include <stddef.h>
#include <errno.h>
#include <unistd.h>     // for fork, pid_t
#include <sys/ptrace.h> // for ptrace, PTRACE_*
#include <sys/user.h>   // for struct user_regs_struct
#include <sys/wait.h>   // for waitpid, WSTOPSIG
#include <capstone/capstone.h>
#include "tracer.h"
#include "dwarf/dl_parser.h"

#define BOX_TOP     "╔══════════════════════════════╗"
#define BOX_SIDE    "║"
#define BOX_DIVIDER "╠══════════════════════════════╣"
#define BOX_BOTTOM  "╚══════════════════════════════╝"
#define CLEAR_SCREEN "\x1b[1;1H\x1b[2J"

#define MAX_BREAKPOINTS 16

typedef struct {
    uintptr_t addr;
    uint8_t   orig_byte;
    bool      active;
} Breakpoint;

static Breakpoint bptable[MAX_BREAKPOINTS];

static void die(char *s) {
    puts(s);
    exit(EXIT_FAILURE);
}

static void err_check(void) {
    switch (errno) {
        case EBUSY:  die("ptrace: EBUSY");
        case EFAULT: die("ptrace: EFAULT");
        case EINVAL: die("ptrace: EINVAL");
        case EIO:    die("ptrace: EIO");
        case EPERM:  die("ptrace: EPERM");
        case ESRCH:  die("ptrace: ESRCH");
        default:     die("ptrace: unknown error");
    }
}

static long ptrace_or_die(enum __ptrace_request op, pid_t pid, void *addr, void *data) {
    long result = ptrace(op, pid, addr, data);
    if (result == -1)
        die("ptrace failed!");
    return result;
}

static uint64_t read_word(pid_t pid, uintptr_t addr) {
    return ptrace_or_die(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
}

static int check_child_ret(pid_t pid) {
    int wstatus;
    if (waitpid(pid, &wstatus, 0) != pid)
        die("waitpid failed");
    return wstatus;
}


static void print_regs(struct user_regs_struct regs) {
    puts(BOX_TOP);
    printf(BOX_SIDE "    rax: 0x%016llx   " BOX_SIDE "\n", regs.rax);
    printf(BOX_SIDE "    rbx: 0x%016llx   " BOX_SIDE "\n", regs.rbx);
    printf(BOX_SIDE "    rcx: 0x%016llx   " BOX_SIDE "\n", regs.rcx);
    printf(BOX_SIDE "    rdx: 0x%016llx   " BOX_SIDE "\n", regs.rdx);
    printf(BOX_SIDE "    rdi: 0x%016llx   " BOX_SIDE "\n", regs.rdi);
    printf(BOX_SIDE "    rsi: 0x%016llx   " BOX_SIDE "\n", regs.rsi);
    printf(BOX_SIDE "     r8: 0x%016llx   " BOX_SIDE "\n", regs.r8);
    printf(BOX_SIDE "     r9: 0x%016llx   " BOX_SIDE "\n", regs.r9);
    printf(BOX_SIDE "    r10: 0x%016llx   " BOX_SIDE "\n", regs.r10);
    printf(BOX_SIDE "    r11: 0x%016llx   " BOX_SIDE "\n", regs.r11);
    printf(BOX_SIDE "    r12: 0x%016llx   " BOX_SIDE "\n", regs.r12);
    printf(BOX_SIDE "    r13: 0x%016llx   " BOX_SIDE "\n", regs.r13);
    printf(BOX_SIDE "    r14: 0x%016llx   " BOX_SIDE "\n", regs.r14);
    printf(BOX_SIDE "    r15: 0x%016llx   " BOX_SIDE "\n", regs.r15);
    printf(BOX_SIDE "    rip: 0x%016llx   " BOX_SIDE "\n", regs.rip);
    printf(BOX_SIDE "    rbp: 0x%016llx   " BOX_SIDE "\n", regs.rbp);
    printf(BOX_SIDE "    rsp: 0x%016llx   " BOX_SIDE "\n", regs.rsp);
    printf(BOX_SIDE " eflags: 0x%016llx   " BOX_SIDE "\n", regs.eflags);
    puts(BOX_BOTTOM);
    puts("");
}

static csh cs_open_or_die(void) {
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        die("cs_open failed!");
    return handle;
}

static void disas_rip(pid_t pid) {
    csh cs_handle = cs_open_or_die();

    struct user_regs_struct regs = {};
    ptrace_or_die(PTRACE_GETREGS, pid, NULL, &regs);

    uintptr_t start = (regs.rip - 15) & ~(uintptr_t)7;
    uint64_t buf[5];
    for (int i = 0; i < 5; i++)
        buf[i] = read_word(pid, start + i * 8);

    cs_insn *insns;
    size_t count = cs_disasm(cs_handle, (uint8_t *)buf, sizeof(buf), start, 0, &insns);
    if (count == 0)
        die("cs_disasm failed!");

    int idx = -1;
    for (size_t i = 0; i < count; i++) {
        if (insns[i].address == regs.rip) {
            idx = (int)i;
            break;
        }
    }

    puts("──────────────────────────────────");
    if (idx > 0)
        printf("     0x%012llx  %-8s %s\n",
               insns[idx-1].address, insns[idx-1].mnemonic, insns[idx-1].op_str);
    if (idx >= 0)
        printf(" ──► 0x%012llx  %-8s %s\n",
               insns[idx].address,   insns[idx].mnemonic,   insns[idx].op_str);
    if (idx >= 0 && idx + 1 < (int)count)
        printf("     0x%012llx  %-8s %s\n",
               insns[idx+1].address, insns[idx+1].mnemonic, insns[idx+1].op_str);
    puts("──────────────────────────────────");

    cs_free(insns, count);
    cs_close(&cs_handle);
}

static void d_regs(pid_t pid) {
    struct user_regs_struct regs = {};
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
        err_check();
    print_regs(regs);
}

static void display_info(pid_t pid) {
    printf("%s", CLEAR_SCREEN);
    d_regs(pid);
    disas_rip(pid);
    for (int i = 0; i < MAX_BREAKPOINTS; i++)
        if (bptable[i].active)
            printf("breakpoint %d: 0x%012lx\n", i, bptable[i].addr);
    puts("Enter: [s] single step | [n] next (step over) | [f] finish (step out) | [c] continue | [b] set breakpoint");
}


static bool single_step(pid_t pid) {
    long ret = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    int wstatus = check_child_ret(pid);

    if (ret == -1)
        err_check();
    if (WIFEXITED(wstatus)) {
        puts("Tracee exited.");
        return false;
    }
    if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP)
        puts("Tracee stopped.");
    return true;
}

static bool cont(pid_t pid) {
    long ret = ptrace(PTRACE_CONT, pid, NULL, NULL);
    int wstatus = check_child_ret(pid);

    if (ret == -1)
        err_check();
    if (WIFEXITED(wstatus)) {
        puts("Tracee exited.");
        return false;
    }
    if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP) {
        handle_bp_hit(pid);
        puts("Tracee stopped.");
    }
    return true;
}

static bool next_i(pid_t pid) {
    csh cs_handle = cs_open_or_die();

    struct user_regs_struct regs = {};
    ptrace_or_die(PTRACE_GETREGS, pid, NULL, &regs);

    uintptr_t start = (regs.rip - 15) & ~(uintptr_t)7;
    uint64_t buf[5];
    for (int i = 0; i < 5; i++)
        buf[i] = read_word(pid, start + i * 8);

    cs_insn *insns;
    size_t count = cs_disasm(cs_handle, (uint8_t *)buf, sizeof(buf), start, 0, &insns);
    cs_close(&cs_handle);
    if (count == 0)
        die("cs_disasm failed!");

    int idx = -1;
    for (size_t i = 0; i < count; i++) {
        if (insns[i].address == regs.rip) {
            idx = (int)i;
            break;
        }
    }

    bool is_call = idx >= 0 && strcmp(insns[idx].mnemonic, "call") == 0;
    uint64_t next_addr = idx >= 0 ? insns[idx].address + insns[idx].size : 0;
    cs_free(insns, count);

    if (is_call) {
        set_breakpoint(pid, (void *)next_addr);
        return cont(pid);
    } else {
        return single_step(pid);
    }
}

static bool step_out(pid_t pid) {
    struct user_regs_struct regs = {};
    ptrace_or_die(PTRACE_GETREGS, pid, NULL, &regs);
    uint64_t return_addr = read_word(pid, regs.rsp);
    set_breakpoint(pid, (void *)return_addr);
    return cont(pid);
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

unsigned long get_base_address(pid_t pid) {
    char path[256];
    sprintf(path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        puts("Failed to open /proc/pid/maps");
        return 0;
    }
    unsigned long base = 0;
    fscanf(f, "%lx", &base);
    printf("base: %lx\n", base);
    fclose(f);
    return base;
}


// TODO: clear breakpoint function

int ptrace_init(const char *target_path) {
    pid_t tracee_pid = fork();

    if (tracee_pid == 0) {
        // child: become the tracee
        puts("Child: Tracing this process.\n");
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(target_path, target_path, NULL);
        die("execl failed");
    }

    // parent: control the child
    unsigned long offset = (unsigned long)get_first_func_address(target_path);
    printf("checking :%lx\n", offset);

    int status;
    waitpid(tracee_pid, &status, 0);
    if (WIFSTOPPED(status))
        printf("Parent: Child stoppped, starting ptrace operations.\n");

    unsigned long base = get_base_address(tracee_pid);
    if (base != 0)
        set_breakpoint(tracee_pid, (void *)(base + offset));

    bool running = true;
    while (running) {
        display_info(tracee_pid);

        char *line = NULL;
        size_t size = 0;
        ssize_t nread = getdelim(&line, &size, '\n', stdin);

        if (nread == 2) {
            switch (line[0]) {
                case 's':
                    puts("step");
                    running &= single_step(tracee_pid);
                    break;
                case 'c':
                    puts("continue");
                    running &= cont(tracee_pid);
                    break;
                case 'n':
                    puts("next");
                    running &= next_i(tracee_pid);
                    break;
                case 'f':
                    puts("finish");
                    running &= step_out(tracee_pid);
                    break;
                case 'b': {
                    printf("Enter address: 0x");
                    nread = getline(&line, &size, stdin);
                    char *endptr;
                    unsigned long addr = strtoul(line, &endptr, 16);
                    printf("set breakpoint at: 0x%lx\n", addr);
                    set_breakpoint(tracee_pid, (void *)addr);
                    break;
                }
                default:
                    puts("Error: unknown command");
            }
        } else {
            puts("invalid command");
        }

        fflush(stdout);
        free(line);
    }

    puts("Parent: child process has exited.");
    return 0;
}

int main(int argc, char **argv) {
    if (argc <= 1) {
        puts("Usage: ptracer <target>");
        return -1;
    }
    ptrace_init(argv[1]);
    return 0;
}
