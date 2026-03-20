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

#define BOX_TOP     "╔══════════════════════════════╗"
#define BOX_SIDE    "║"
#define BOX_DIVIDER "╠══════════════════════════════╣"
#define BOX_BOTTOM  "╚══════════════════════════════╝"
#define CLEAR_SCREEN "\x1b[1;1H\x1b[2J"

#define BOLD    "\x1b[1m"
#define DIM     "\x1b[2m"
#define CYAN    "\x1b[96m"
#define RESET   "\x1b[0m"

#define MAX_BREAKPOINTS 16

typedef struct {
    uintptr_t addr;
    uint8_t   orig_byte;
    bool      active;
} Breakpoint;

static Breakpoint bptable[MAX_BREAKPOINTS];

static bool handle_bp_hit(pid_t pid);
unsigned long base = 0;
uintptr_t prev = 0;
int64_t v_addy;
int r_size = 0;

__attribute__((noreturn)) static void die(char *s) {
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
        err_check();
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

static void parse_stack(uintptr_t initial_rsp, uintptr_t end_rsp, uintptr_t rbp, pid_t pid) {

    puts(BOX_TOP);

    uintptr_t current_slot = initial_rsp;
    if (current_slot - end_rsp >= (64)) {
        current_slot = end_rsp + 64;
    }

    unsigned long stack_start, stack_end;
    get_stack_range(pid, &stack_start, &stack_end);

    while (current_slot >= end_rsp - 8) {
        if (current_slot < stack_start || current_slot >= stack_end) {
            break;
        }
        uint64_t stack_value = read_word(pid, current_slot);
        printf(BOX_SIDE "      0x%016" PRIx64 "      " BOX_SIDE "\n",
               stack_value);

        if (current_slot != end_rsp - 8) {
            if (current_slot == end_rsp && current_slot == rbp) {
                printf(BOX_DIVIDER " ← rsp, rbp\n");

            } else if (current_slot == end_rsp) {
                printf(BOX_DIVIDER " ← rsp\n");
            } else if (current_slot == rbp) {
                printf(BOX_DIVIDER " ← rbp\n");
            } else {
                printf(BOX_DIVIDER "\n");
            }
        }
        current_slot -= 8;
    }
    // printf(BOX_BOTTOM " ← rsp\n");
    printf(BOX_BOTTOM "\n");
}

static csh cs_open_or_die(void) {
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        die("cs_open failed!");
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    return handle;
}

static void disas_rip(pid_t pid, Matrix *m) {
    csh cs_handle = cs_open_or_die();

    struct user_regs_struct regs = {};
    ptrace_or_die(PTRACE_GETREGS, pid, NULL, &regs);

    uintptr_t start = (regs.rip);
    uint64_t buf[4];
    for (int i = 0; i < 4; i++)
        buf[i] = read_word(pid, start + i * 8);

    uint64_t prev_buf[2];
    cs_insn *prev_ins;
    size_t p_count;
    if (prev != 0) {
        for(int i = 0; i < 2; i++) {
            prev_buf[i] = read_word(pid, prev + i * 8);
        }

        p_count = cs_disasm(cs_handle, (uint8_t *)prev_buf, sizeof(prev_buf), prev, 1, &prev_ins);
    }
    cs_insn *insns;
    size_t count = cs_disasm(cs_handle, (uint8_t *)buf, sizeof(buf), start, 0, &insns);

    if (count == 0)
        die("cs_disasm failed!");


    

    puts("──────────────────────────────────");
    int64_t line;
    if (prev != 0) {
        line = get_line(m, prev_ins[0].address);
        printf("     0x%012lx  %-8s %s > line %ld\n",
               prev_ins[0].address, prev_ins[0].mnemonic, prev_ins[0].op_str, line);
        cs_free(prev_ins, p_count);
    }
    line = get_line(m, insns[0].address);
    printf(" ──► 0x%012lx  %-8s %s > line %ld\n",
           insns[0].address,   insns[0].mnemonic,   insns[0].op_str, line);

    if (count > 1) {
        line = get_line(m, insns[1].address);
        printf("     0x%012lx  %-8s %s > line %ld\n",
               insns[1].address, insns[1].mnemonic, insns[1].op_str, line);
    }
    puts("──────────────────────────────────");

    cs_detail *detail = insns->detail;
    cs_x86 x86 = detail->x86;

    if (x86.op_count == 2) {
        cs_x86_op op; 
        cs_x86_op op1;

        op = x86.operands[0];
        op1 = x86.operands[1];
        uint8_t op1_size = op1.size;
        cs_ac_type write = CS_AC_WRITE;

        if (op.type == X86_OP_MEM && write == op.access) {

            x86_op_mem mem = op.mem;
            x86_reg segment = mem.segment;
            x86_reg sbase = mem.base;
            x86_reg index = mem.index;
            int scale = mem.scale;
            int64_t disp = mem.disp;
            int64_t addy = disp;

            if (segment != X86_REG_INVALID) {

            } else {
                //puts("segment invalid");  
            }
            if (sbase != X86_REG_INVALID) {
                addy += get_regs(regs, sbase);                
            } else {
                //puts("base invalid");
            }
            if (index != X86_REG_INVALID) {
                // scale the index
                addy += (scale * get_regs(regs, index));
            }else {
                //puts("index invalid");
            }

            uint8_t *t_buf = malloc(op1_size * sizeof(uint8_t));
            get_n_bytes(t_buf, op1_size, pid, addy);

            //printf("size to read from: %d\n", op1_size);
            printf("pre-write @ %lx: ", addy);
            for(int i = 0; i < op1_size; i++) {
                printf("%02x ", t_buf[i]);
            }
            puts("");
            r_size = op1_size;
            v_addy = addy;
            free(t_buf);
        }

    }

    prev = regs.rip;
    cs_free(insns, count);
    cs_close(&cs_handle);
}


static void display_info(pid_t pid, Matrix *m, uintptr_t initial_rsp) {
    printf("%s", CLEAR_SCREEN);

    struct user_regs_struct regs = {};
    ptrace_or_die(PTRACE_GETREGS, pid, NULL, &regs);
    print_regs(regs);

    if (r_size > 0) {
        uint8_t *vbuf = malloc(r_size * sizeof(uint8_t));
        get_n_bytes(vbuf, r_size, pid, v_addy);
        printf("recent write @ %lx: ", v_addy);
        for(int i = 0; i < r_size; i++) {
             printf("%02x ", vbuf[i]);
        }
        puts("");
        free(vbuf);
    }

    disas_rip(pid, m);




    for (int i = 0; i < MAX_BREAKPOINTS; i++)
        if (bptable[i].active)
            printf("breakpoint %d: 0x%012lx\n", i, bptable[i].addr);
    puts(DIM "──────────────────────────────────" RESET);
    printf("  " BOLD CYAN "s" RESET " step    "
           BOLD CYAN "n" RESET " next    "
           BOLD CYAN "f" RESET " finish    "
           BOLD CYAN "c" RESET " continue    "
           BOLD CYAN "b" RESET " breakpoint    "
           BOLD CYAN "d" RESET " delete bp    "
           BOLD CYAN "q" RESET " quit\n");

    parse_stack(initial_rsp, regs.rsp, regs.rbp, pid);
    get_base_address(pid);

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

    // recent write

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

    uintptr_t start = regs.rip;
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


int get_stack_range(pid_t pid, unsigned long *start, unsigned long *end) {
    char path[256], line[512];
    sprintf(path, "/proc/%d/maps", pid);
    
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "[stack]")) {
            sscanf(line, "%lx-%lx", start, end);
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    return -1;
}

int get_base_address(pid_t pid) {
    char path[256];
    sprintf(path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        puts("Failed to open /proc/pid/maps");
        return -1;
    }
    // int ch;
    // while((ch = getc(f)) != EOF) {
    //     putchar(ch); 
    // }
    // rewind(f);

    fscanf(f, "%lx", &base);
    //printf("base: %lx\n", base);
    fclose(f);
    return 1;
}

uint64_t get_line(Matrix *m, uint64_t address) {

    for(size_t i = 0; i < m->count-1; i++) {
        if (address <= base+m->arr[i]->address) {
            return m->arr[i]->line;
        }
    }
    return -1;
}

int ptrace_init(const char *target_path, Matrix *m) {
    pid_t tracee_pid = fork();

    if (tracee_pid == 0) {
        // child: become the tracee
        puts("Child: Tracing this process.\n");
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(target_path, target_path, NULL);
        die("execl failed");
    }
    unsigned long offset = m->arr[0]->address;

    // parent: control the child
    //unsigned long offset = (unsigned long)get_first_func_address(target_path);
    printf("checking :%lx\n", offset);

    int status;
    waitpid(tracee_pid, &status, 0);
    if (WIFSTOPPED(status))
        printf("Parent: Child stoppped, starting ptrace operations.\n");

    struct user_regs_struct regs = {};
    ptrace_or_die(PTRACE_GETREGS, tracee_pid, NULL, &regs);
    uintptr_t initial_rsp = regs.rsp;

    //unsigned long base = dump_dl(tracee_pid);
    get_base_address(tracee_pid);
    if (base != 0)
        set_breakpoint(tracee_pid, (void *)(base + offset));

    bool running = true;
    while (running) {
        display_info(tracee_pid, m, initial_rsp);


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
                case 'd': {
                    printf("Enter breakpoint index: ");
                    nread = getline(&line, &size, stdin);
                    int idx = (int)strtol(line, NULL, 10);
                    if (idx >= 0 && idx < MAX_BREAKPOINTS && bptable[idx].active) {
                        clear_breakpoint(tracee_pid, bptable[idx].addr);
                        printf("cleared breakpoint %d\n", idx);
                    } else {
                        printf("no active breakpoint at index %d\n", idx);
                    }
                    break;
                }
                case 'q':
                    kill(tracee_pid, SIGKILL);
                    puts("Tracee killed.");
                    running = false;
                    break;
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
    const char* target_path = argv[1];
    Matrix *m = initialize_matrix();
    dump_dl(target_path, m);
    ptrace_init(target_path, m);

    for(size_t i = 0; i < m->count; i++) {
        free(m->arr[i]);
        m->arr[i] = NULL;
    }
    free(m->arr);
    m->arr = NULL;
    free(m);

    return 0;
}
