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
#include "tracer.h"

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
int stop_status(int status) {
    if (WIFSTOPPED(status)) {
        printf("child stopped\n");

    }

}

int ptrace_init(const char* target_path) {
    pid_t child_pid = fork();
    if (child_pid == 0) {
        // child process: run the target program
        puts("Child: Tracing this process.\n");
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(target_path, target_path, NULL);

    } else {
        // Parent process: Attach and control the child
        int status;
        waitpid(child_pid, &status, 0); // wait for the child to stop
        if (WIFSTOPPED(status)) {
            printf("Parent: child stopped, starting ptrace operations.\n");

        while(1) {

            printf("Parent: Child stoppped, starting ptrace operations.\n");
            ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);

        }

        }

        ptrace(PTRACE_CONT, child_pid, NULL, NULL); // continue child execution
        wait(NULL); // wait for child to complete
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
