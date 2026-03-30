#pragma once
#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <stdbool.h>


typedef struct __attribute__((packed)) {
    uint32_t length;
    uint16_t version;
    uint8_t address_size;
    uint8_t segment_selector_size;
    uint32_t header_length;
    uint8_t min_instruction_length; // segment selector
    uint8_t max_ops_per_instruction;
    uint8_t default_is_smt;
    int8_t line_base;
    uint8_t line_range;
    uint8_t opcode_base;
    // uint8_t std_opcode_lengths[12]; // this can change, if opcode_base is increased
} DebugLineHeader;

typedef struct __attribute__((packed)) {
    uint64_t address; // the program-counter value corresponding to a machine instruction generated
                      // by the compiler
    uint64_t op_index; // unsigned integer rep the index of an operation within a VLIW ins...
                       // for non-vliw arch, this register will always be 0
    uint64_t file;  // uint indicating the identity of the source file corresponsing to a machine instrcution
    uint64_t line; // uint indicating source line number. lines are numbered beginning at 1.
    uint64_t column; // uint indicating a col number within a source line. col numbered beginning at 1
    bool is_stmt; // boolean indicating currnet instruction is a recommended breakpoint location.
    bool basic_block; // boolean indicating that the current instruction is the beginning of
                         // a basic block
    bool end_sequence; // boolean indcitin the current address is taht of the first bytes after
                          // the end of a sequence of target machine instructions.
    bool prologue_end; // boolean indicating that the current address is one where execution
                          // should be suspended for a breakpoint at the entry of a function
    bool epilogue_begin; // a boolean indicating that the current address is one where execution
                            // should be suspended for a breakpoint just priour to the exit of a
                            // function
    uint64_t isa; // an uint whose value encodes the application inst set arch for the current inst
    uint64_t discriminator;


} ProgramRegisterState;

typedef struct {
    ProgramRegisterState **arr;
    size_t count;
    size_t capacity;

} Matrix;



uint64_t get_first_func_address(char *filepath);
int dump_dl(const char *filepath, Matrix *m);
uint64_t decode_uleb128(uint8_t **ptr);
int64_t decode_sleb128(uint8_t **ptr);
Matrix *initialize_matrix();
void initialize_default_state(ProgramRegisterState *state_arr);
void add_row(Matrix *m, ProgramRegisterState dummy);
Elf64_Shdr * get_section(Elf64_Shdr **shdr_array, uint16_t sh_num, const char * cmp, char *str_tab);
