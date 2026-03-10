#include <elf.h>    // for Elf64_Shdr, Elf64_Section
#include <fcntl.h>  // for open, O_RDONLY
#include <gelf.h>   // for GElf_Sym, gelf_getsym
#include <libelf.h> // for elf_version, elf_begin, elf_getscn, elf_nextscn, Elf, Elf_Scn, elf64_getshdr, Elf_Data, elf_getdata
#include <limits.h> // for CHAR_BIT
#include <signal.h> // for SIG*
#include <stdint.h> // for uint*_t
#include <stdio.h>  // for puts, printf, getline
#include <stdlib.h> // for exit, EXIT_FAILURE, NULL
#include <string.h> // for memcpy
#include <sys/ptrace.h> // for ptrace, PTRACE_*
#include <sys/user.h>   // for struct user_regs_struct
#include <sys/wait.h>   // for waitpid, WSTOPSIG
#include <unistd.h>     // for fork, pid_t
#include <errno.h>
#include <stddef.h>
#include "tracer.h"
#include "dwarf/dl_parser.h"

#include <capstone/capstone.h>

#define BOX_TOP "╔══════════════════════════════╗"
#define BOX_SIDE "║"
#define BOX_DIVIDER "╠══════════════════════════════╣"
#define BOX_BOTTOM "╚══════════════════════════════╝"
#define CLEAR_SCREEN "\x1b[1;1H\x1b[2J"


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
static void die(char *s) {
    puts(s);
    exit(EXIT_FAILURE);
}


static void err_check() {
    switch(errno) {
        case EBUSY:
            die("ptrace: errno - EBUSY");
            break;
        case EFAULT:
            die("ptrace: errno - EFAULT");
            break;
        case EINVAL:
            die("ptrace: errno - EINVAL");
            break;
        case EIO:
            die("ptrace: errno - EIO");
            break;
        case EPERM:
            die("ptrace: errno - EPERM");
            break;
        case ESRCH:
            die("ptrace: errno - ESRCH");
            break;
        default:
            die("unkown error # from ptrace");
    }
}

static int check_child_ret(pid_t tracee_pid) {
    int wstatus;
    if (waitpid(tracee_pid, &wstatus, 0) != tracee_pid) {
        // waitpid failed
        die("waitpid failed");
    }

    return wstatus;
}

static bool single_step(pid_t tracee_pid) {

    int wstatus;
    long ret = ptrace(PTRACE_SINGLESTEP, tracee_pid, NULL, NULL);
    wstatus = check_child_ret(tracee_pid);

    if (ret == -1) {
        err_check();
    }

    if (WIFEXITED(wstatus)) { // if the child terminated
        puts("Tracee exited.");
        return false;

    } else if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP) { // if tracee was stopped by signal delivery
        puts("Tracee stopped.");
        return true;
    }

    return true;
}

static void set_breakpoint(pid_t tracee_pid, void *address) {
    struct user_regs_struct regs;

    ptrace(PTRACE_POKEUSER, tracee_pid, offsetof(struct user, u_debugreg[0]), address);

    unsigned long dr7 = 0x00000002;
    
    ptrace(PTRACE_POKEUSER, tracee_pid, offsetof(struct user, u_debugreg[7]), dr7);


}

static bool next_i(pid_t tracee_pid) {
    return false;
}

static bool cont(pid_t tracee_pid) {
    int wstatus;
    long ret = ptrace(PTRACE_CONT, tracee_pid, NULL, NULL);
    wstatus = check_child_ret(tracee_pid);
    if (ret == -1) {
        err_check();
    }
    if (WIFEXITED(wstatus)) {
        puts("Tracee exited.");
        return false;
    } else if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP) {
        puts("Tracee stopped.");
        return true;
    }
    return true; 
}

static void d_regs(pid_t tracee_pid) {
    struct user_regs_struct regs = {};
    long ret = ptrace(PTRACE_GETREGS, tracee_pid, NULL, &regs);
    if (ret == -1) {
        err_check();
    }
    print_regs(regs);
}

static void display_info(pid_t tracee_pid) {
    printf("%s", CLEAR_SCREEN);
    
    // display regs
    d_regs(tracee_pid);
    // display current breakpoints set;

    puts("Enter: [s] - single step instruction; [c] - continue; [b] - set breakpoint;");
}

unsigned long get_base_address(pid_t pid) {
    char path[256];
    sprintf(path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        puts("Failed to open /proc/pid/map");
        return 0;
    }
    unsigned long base = 0;
    fscanf(f, "%lx", &base);
    printf("base: %lx\n", base);
    fclose(f);
    return base;

}

int ptrace_init(const char* target_path) {
    



    pid_t tracee_pid = fork();
    if (tracee_pid == 0) {
        // child process: run the target program
        puts("Child: Tracing this process.\n");
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(target_path, target_path, NULL);

    } else {
        // Parent process: Attach and control the child
        unsigned long offset = (unsigned long)get_first_func_address(target_path); 

        printf("checking :%lx\n", offset);
        int status;
        bool change = true;
        waitpid(tracee_pid, &status, 0); // wait for the child to stop
        if (WIFSTOPPED(status)) {

            printf("Parent: Child stoppped, starting ptrace operations.\n");

        }

        unsigned long base = get_base_address(tracee_pid);
        if (base != 0) { 
            unsigned long target_addr = base + offset;
            // set breakpoint at main -> main has to be first function
            set_breakpoint(tracee_pid, (void*)target_addr);
        }

        while(change) {

            
            display_info(tracee_pid);


            char *line = NULL;
            size_t size = 0;
            ssize_t nread;
            nread = getdelim(&line, &size, '\n', stdin);

            if (nread == 2) {
                int input = line[0];
                switch(input) {
                    case 's': // single step into inst
                        puts("step");
                        change &= single_step(tracee_pid);
                        break;
                    case 'c': // continue to breakpoint/end
                        puts("continue");
                        change &= cont(tracee_pid);
                        break;
                    case 'n': // next instruction
                        break;
                    case 'b': // set breakpoint
                        printf("Enter address: 0x");
                        nread = getline(&line, &size, stdin);
                        char *endptr;
                        unsigned long addy = strtoul(line, &endptr, 16);
                        // TODO: check if the address is a valid address
                        printf("set breakpoint at: %lx", addy);
                        set_breakpoint(tracee_pid, (void*)addy);
                        break;
                    default:
                        puts("Error: invalid code"); 

                }
            } else {
                puts("invalid command");
            }
            fflush(stdout);
            free(line);
        }

        printf("Parent: Child process has exited.\n");
    }
        

    return 0;
}


int main(int argc, char** argv) {

    if (argc <=1 ) {
        printf("Error: \n");
        return -1;
    }


    const char* target_path = argv[1];
    ptrace_init(target_path);


}
