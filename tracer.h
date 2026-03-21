#include <sys/ptrace.h>
#include <sys/uio.h>
#include "dwarf/dl_parser.h"

static void parse_stack(uintptr_t initial_rsp, uintptr_t end_rsp, uintptr_t rbp, pid_t pid);
static void print_regs(struct user_regs_struct regs);
static void die(char *s);
static void err_check();
static int check_child_ret(pid_t tracee_pid);
static bool single_step(pid_t tracee_pid);
static bool next_i(pid_t tracee_pid);
static bool cont(pid_t tracee_pid);
static void display_info(pid_t tracee_pid, Matrix *m, uintptr_t initial_rsp);
static void set_breakpoint(pid_t tracee_pid, void * address);
int stop_status(int status);
int ptrace_init(const char* target_path, Matrix *m);
static long ptrace_or_die(enum __ptrace_request op, pid_t pid, void *addr, void *data); 
int get_n_bytes(void *buf, uint8_t size, pid_t pid, int64_t addr);
static void disas_rip(pid_t pid, Matrix *m); 
uint64_t get_line(Matrix *m, uint64_t address);
int get_base_address(pid_t pid);
int get_stack_range(pid_t pid, unsigned long *start, unsigned long *end);

int get_n_bytes(void *buf, uint8_t size, pid_t pid, int64_t addr) {   
    int count = 0;
    uint8_t *ptr = buf;
    
    while(count < size) {
        int64_t aligned_addr = (addr + count) & ~0x7;
        
        int offset = (addr + count) % 8;

        long res = ptrace_or_die(PTRACE_PEEKDATA, pid, (void *)aligned_addr, NULL);
                          
        int bytes_in_word = 8 - offset;
        int bytes_left = size - count;
        int copy_size = (bytes_left < bytes_in_word) ? bytes_left : bytes_in_word;
                                            
        memcpy(ptr + count, ((uint8_t *)&res) + offset, copy_size);
        
        count += copy_size;
    }
    return 0;
}


uint64_t get_regs(struct user_regs_struct regs, int x86_reg) {

    uint64_t res;

    switch(x86_reg) {
        case X86_REG_AH:
			break;
        case X86_REG_AL:
			break;
        case X86_REG_AX:
			break;
        case X86_REG_BH:
			break;
        case X86_REG_BL:
			break;
        case X86_REG_BP:
			break;
        case X86_REG_BPL:
			break;
        case X86_REG_BX:
			break;
        case X86_REG_CH:
			break;
        case X86_REG_CL:
			break;
        case X86_REG_CS:
			break;
        case X86_REG_CX:
			break;
        case X86_REG_DH:
			break;
        case X86_REG_DI:
			break;
        case X86_REG_DIL:
			break;
        case X86_REG_DL:
			break;
        case X86_REG_DS:
			break;
        case X86_REG_DX:
			break;
        case X86_REG_EAX:
            res = regs.rax & 0xFFFFFFFF;
			break;
        case X86_REG_EBP:
			break;
        case X86_REG_EBX:
			break;
        case X86_REG_ECX:
            res = regs.rcx & 0xFFFFFFFF;
			break;
        case X86_REG_EDI:
            res = regs.rdi & 0xFFFFFFFF;
			break;
        case X86_REG_EDX:
            res = regs.rdx & 0xFFFFFFFF;
			break;
        case X86_REG_EFLAGS:
			break;
        case X86_REG_EIP:
			break;
        case X86_REG_EIZ:
			break;
        case X86_REG_ES:
			break;
        case X86_REG_ESI:
            res = regs.rdx & 0xFFFFFFFF;
			break;
        case X86_REG_ESP:
			break;
        case X86_REG_FPSW:
			break;
        case X86_REG_FS:
			break;
        case X86_REG_GS:
			break;
        case X86_REG_IP:
			break;
        case X86_REG_RAX:
            res = regs.rax;
			break;
        case X86_REG_RBP:
            res = regs.rbp;
			break;
        case X86_REG_RBX:
            res = regs.rbx;
			break;
        case X86_REG_RCX:
            res = regs.rcx;
			break;
        case X86_REG_RDI:
            res = regs.rdi;
			break;
        case X86_REG_RDX:
            res = regs.rdx;
			break;
        case X86_REG_RIP:
            res = regs.rip;
			break;
        case X86_REG_RIZ:
			break;
        case X86_REG_RSI:
            res = regs.rsi;
			break;
        case X86_REG_RSP:
            res = regs.rsp;
			break;
        case X86_REG_SI:
			break;
        case X86_REG_SIL:
			break;
        case X86_REG_SP:
			break;
        case X86_REG_SPL:
			break;
        case X86_REG_SS:
			break;
        case X86_REG_CR0:
			break;
        case X86_REG_CR1:
			break;
        case X86_REG_CR2:
			break;
        case X86_REG_CR3:
			break;
        case X86_REG_CR4:
			break;
        case X86_REG_CR5:
			break;
        case X86_REG_CR6:
			break;
        case X86_REG_CR7:
			break;
        case X86_REG_CR8:
			break;
        case X86_REG_CR9:
			break;
        case X86_REG_CR10:
			break;
        case X86_REG_CR11:
			break;
        case X86_REG_CR12:
			break;
        case X86_REG_CR13:
			break;
        case X86_REG_CR14:
			break;
        case X86_REG_CR15:
			break;
        case X86_REG_DR0:
			break;
        case X86_REG_DR1:
			break;
        case X86_REG_DR2:
			break;
        case X86_REG_DR3:
			break;
        case X86_REG_DR4:
			break;
        case X86_REG_DR5:
			break;
        case X86_REG_DR6:
			break;
        case X86_REG_DR7:
			break;
        case X86_REG_DR8:
			break;
        case X86_REG_DR9:
			break;
        case X86_REG_DR10:
			break;
        case X86_REG_DR11:
			break;
        case X86_REG_DR12:
			break;
        case X86_REG_DR13:
			break;
        case X86_REG_DR14:
			break;
        case X86_REG_DR15:
			break;
        case X86_REG_FP0:
			break;
        case X86_REG_FP1:
			break;
        case X86_REG_FP2:
			break;
        case X86_REG_FP3:
			break;
        case X86_REG_FP4:
			break;
        case X86_REG_FP5:
			break;
        case X86_REG_FP6:
			break;
        case X86_REG_FP7:
			break;
        case X86_REG_K0:
			break;
        case X86_REG_K1:
			break;
        case X86_REG_K2:
			break;
        case X86_REG_K3:
			break;
        case X86_REG_K4:
			break;
        case X86_REG_K5:
			break;
        case X86_REG_K6:
			break;
        case X86_REG_K7:
			break;
        case X86_REG_MM0:
			break;
        case X86_REG_MM1:
			break;
        case X86_REG_MM2:
			break;
        case X86_REG_MM3:
			break;
        case X86_REG_MM4:
			break;
        case X86_REG_MM5:
			break;
        case X86_REG_MM6:
			break;
        case X86_REG_MM7:
			break;
        case X86_REG_R8:
            res = regs.r8;
			break;
        case X86_REG_R9:
            res = regs.r9;
			break;
        case X86_REG_R10:
            res = regs.r10;
			break;
        case X86_REG_R11:
            res = regs.r11;
			break;
        case X86_REG_R12:
            res = regs.r12;
			break;
        case X86_REG_R13:
            res = regs.r13;
			break;
        case X86_REG_R14:
            res = regs.r14;
			break;
        case X86_REG_R15:
            res = regs.r15;
			break;
        case X86_REG_ST0:
			break;
        case X86_REG_ST1:
			break;
        case X86_REG_ST2:
			break;
        case X86_REG_ST3:
			break;
        case X86_REG_ST4:
			break;
        case X86_REG_ST5:
			break;
        case X86_REG_ST6:
			break;
        case X86_REG_ST7:
			break;
        case X86_REG_XMM0:
			break;
        case X86_REG_XMM1:
			break;
        case X86_REG_XMM2:
			break;
        case X86_REG_XMM3:
			break;
        case X86_REG_XMM4:
			break;
        case X86_REG_XMM5:
			break;
        case X86_REG_XMM6:
			break;
        case X86_REG_XMM7:
			break;
        case X86_REG_XMM8:
			break;
        case X86_REG_XMM9:
			break;
        case X86_REG_XMM10:
			break;
        case X86_REG_XMM11:
			break;
        case X86_REG_XMM12:
			break;
        case X86_REG_XMM13:
			break;
        case X86_REG_XMM14:
			break;
        case X86_REG_XMM15:
			break;
        case X86_REG_XMM16:
			break;
        case X86_REG_XMM17:
			break;
        case X86_REG_XMM18:
			break;
        case X86_REG_XMM19:
			break;
        case X86_REG_XMM20:
			break;
        case X86_REG_XMM21:
			break;
        case X86_REG_XMM22:
			break;
        case X86_REG_XMM23:
			break;
        case X86_REG_XMM24:
			break;
        case X86_REG_XMM25:
			break;
        case X86_REG_XMM26:
			break;
        case X86_REG_XMM27:
			break;
        case X86_REG_XMM28:
			break;
        case X86_REG_XMM29:
			break;
        case X86_REG_XMM30:
			break;
        case X86_REG_XMM31:
			break;
        case X86_REG_YMM0:
			break;
        case X86_REG_YMM1:
			break;
        case X86_REG_YMM2:
			break;
        case X86_REG_YMM3:
			break;
        case X86_REG_YMM4:
			break;
        case X86_REG_YMM5:
			break;
        case X86_REG_YMM6:
			break;
        case X86_REG_YMM7:
			break;
        case X86_REG_YMM8:
			break;
        case X86_REG_YMM9:
			break;
        case X86_REG_YMM10:
			break;
        case X86_REG_YMM11:
			break;
        case X86_REG_YMM12:
			break;
        case X86_REG_YMM13:
			break;
        case X86_REG_YMM14:
			break;
        case X86_REG_YMM15:
			break;
        case X86_REG_YMM16:
			break;
        case X86_REG_YMM17:
			break;
        case X86_REG_YMM18:
			break;
        case X86_REG_YMM19:
			break;
        case X86_REG_YMM20:
			break;
        case X86_REG_YMM21:
			break;
        case X86_REG_YMM22:
			break;
        case X86_REG_YMM23:
			break;
        case X86_REG_YMM24:
			break;
        case X86_REG_YMM25:
			break;
        case X86_REG_YMM26:
			break;
        case X86_REG_YMM27:
			break;
        case X86_REG_YMM28:
			break;
        case X86_REG_YMM29:
			break;
        case X86_REG_YMM30:
			break;
        case X86_REG_YMM31:
			break;
        case X86_REG_ZMM0:
			break;
        case X86_REG_ZMM1:
			break;
        case X86_REG_ZMM2:
			break;
        case X86_REG_ZMM3:
			break;
        case X86_REG_ZMM4:
			break;
        case X86_REG_ZMM5:
			break;
        case X86_REG_ZMM6:
			break;
        case X86_REG_ZMM7:
			break;
        case X86_REG_ZMM8:
			break;
        case X86_REG_ZMM9:
			break;
        case X86_REG_ZMM10:
			break;
        case X86_REG_ZMM11:
			break;
        case X86_REG_ZMM12:
			break;
        case X86_REG_ZMM13:
			break;
        case X86_REG_ZMM14:
			break;
        case X86_REG_ZMM15:
			break;
        case X86_REG_ZMM16:
			break;
        case X86_REG_ZMM17:
			break;
        case X86_REG_ZMM18:
			break;
        case X86_REG_ZMM19:
			break;
        case X86_REG_ZMM20:
			break;
        case X86_REG_ZMM21:
			break;
        case X86_REG_ZMM22:
			break;
        case X86_REG_ZMM23:
			break;
        case X86_REG_ZMM24:
			break;
        case X86_REG_ZMM25:
			break;
        case X86_REG_ZMM26:
			break;
        case X86_REG_ZMM27:
			break;
        case X86_REG_ZMM28:
			break;
        case X86_REG_ZMM29:
			break;
        case X86_REG_ZMM30:
			break;
        case X86_REG_ZMM31:
			break;
        case X86_REG_R8B:
			break;
        case X86_REG_R9B:
			break;
        case X86_REG_R10B:
			break;
        case X86_REG_R11B:
			break;
        case X86_REG_R12B:
			break;
        case X86_REG_R13B:
			break;
        case X86_REG_R14B:
			break;
        case X86_REG_R15B:
			break;
        case X86_REG_R8D:
			break;
        case X86_REG_R9D:
			break;
        case X86_REG_R10D:
			break;
        case X86_REG_R11D:
			break;
        case X86_REG_R12D:
			break;
        case X86_REG_R13D:
			break;
        case X86_REG_R14D:
			break;
        case X86_REG_R15D:
			break;
        case X86_REG_R8W:
			break;
        case X86_REG_R9W:
			break;
        case X86_REG_R10W:
			break;
        case X86_REG_R11W:
			break;
        case X86_REG_R12W:
			break;
        case X86_REG_R13W:
			break;
        case X86_REG_R14W:
			break;
        case X86_REG_R15W:
			break;
        case X86_REG_BND0:
			break;
        case X86_REG_BND1:
			break;
        case X86_REG_BND2:
			break;
        case X86_REG_BND3:
			break;
        default:
            break;
    }
    return res;
}
