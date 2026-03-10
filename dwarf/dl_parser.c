#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include "encodings.h"
#include "dl_parser.h"

// source: https://wiki.osdev.org/DWARF#Relocation
/* Source:
 * The content of a the debug sections is broken down by compilation units
 *
*/



#define DW_FORM_string 0x08 // string

Ret debug_init(const char *file_path);
uint64_t get_first_func_address(char *filepath);
int dump_dl(char *filepath);
uint64_t decode_uleb128(uint8_t **ptr);
int64_t decode_sleb128(uint8_t **ptr);
void initialize_default_state(ProgramRegisterState **state_arr);
void append_row_matrix(ProgramRegisterState **state_arr, int row_index);
Elf64_Shdr * get_section(Elf64_Shdr **shdr_array, uint16_t sh_num, const char * cmp, char *str_tab); 

uint64_t get_first_func_address(char *filepath) {
    Ret r = debug_init(filepath);

    void *start = r.start;
    uint8_t *ptr1 = r.ptr1;
    uint8_t opcode_base = r.opcodebase;
    uint8_t min_ins_len = r.min_ins_len;
    uint8_t max_op_inst = r.max_op_inst;
    uint8_t line_range = r.line_range;
    uint8_t line_base = r.line_base;


    size_t allocated_size = 100;
    ProgramRegisterState *state_arr = calloc(allocated_size, sizeof(ProgramRegisterState));
    // initialize default program register state
    initialize_default_state(&state_arr);

    // Line Number Program
    uint8_t * curr;
    int inc = 0;
    uint64_t l_operand;
    int64_t s_operand;
    int adj_opcode;
    int op_advance;
    uint64_t address_inc;

    uint64_t line_offset = (void *)ptr1 - start;

    // printf("\n\n");
    bool flag = false;
    uint64_t ret_addy;
    while ((curr = ptr1++)) {
        // printf("0x%08lx: ", line_offset); 
        // special opcode ranges from 13 to 255
        // the lower bound may increase if one adds new standard opcodes. Thus,26
        // the opcode_base field of the line number program header gives the value of the first27
        // special opcode.
        if (*curr == 0x00) {
            // how many bytes ex opcode spans
            int span = *ptr1++;

            printf("opcode spans %d bytes\n", span);
            uint8_t ex_opcode = *ptr1++;
            switch(ex_opcode) {
                case DW_LNE_set_address:
                    //printf("Setting address\n");
                    uint64_t addy;
                    memcpy(&addy, ptr1, sizeof(uint64_t));
                    ptr1+=sizeof(addy);
                    printf("%x DW_LNS_set_address (0x%016lx)\n",DW_LNE_set_address, addy);
                    line_offset = line_offset + (ptr1 - curr);
                    state_arr[0].address = addy;
                    state_arr[0].op_index = 0;
                    flag = true;
                    ret_addy = addy;
                    break;
                default:
                    break;

            }

        }
        else if (*curr < opcode_base) { // standard opcodes
            switch(*curr) {
                case DW_LNS_set_column:

                    printf("DW_LNS_set_column: %d\n", *curr);
                    uint64_t col_val = decode_uleb128(&ptr1);
                    printf("Checking: %d\n", col_val);
                    line_offset = line_offset + (ptr1 - curr);
                    state_arr[0].column = col_val;
                    printf("%x DW_LNS_SET_column (%d)\n", DW_LNS_set_column, col_val);
                    break;
                default:
                    break;
            }
        }

        if (flag) {
            break;
        }
    }
    free(state_arr);
    return ret_addy;

}

int dump_dl(char *filepath) {
    Ret r = debug_init(filepath);

    void *start = r.start;
    uint8_t *ptr1 = r.ptr1;
    uint8_t opcode_base = r.opcodebase;
    uint8_t min_ins_len = r.min_ins_len;
    uint8_t max_op_inst = r.max_op_inst;
    uint8_t line_range = r.line_range;
    uint8_t line_base = r.line_base;


    size_t allocated_size = 100;
    ProgramRegisterState *state_arr = calloc(allocated_size, sizeof(ProgramRegisterState));
    // initialize default program register state
    initialize_default_state(&state_arr);

    // Line Number Program
    uint8_t * curr;
    int inc = 0;
    uint64_t l_operand;
    int64_t s_operand;
    int adj_opcode;
    int op_advance;
    uint64_t address_inc;

    uint64_t line_offset = (void *)ptr1 - start;

    printf("\n\n");


    while ((curr = ptr1++)) {
        printf("0x%08lx: ", line_offset); 
        // special opcode ranges from 13 to 255
        // the lower bound may increase if one adds new standard opcodes. Thus,26
        // the opcode_base field of the line number program header gives the value of the first27
        // special opcode.
        if (*curr == 0x00) {
            // how many bytes ex opcode spans
            int span = *ptr1++;

            //printf("opcode spans %d bytes\n", span);
            uint8_t ex_opcode = *ptr1++;
            switch(ex_opcode) {
                case DW_LNE_end_sequence: 
                    state_arr[0].end_sequence = true;
                    //printf("Appending to row/ End sequence \n");
                    printf("%x DW_LNE_end_sequence\n", *curr); 

                    printf("            0x%016lx     %d    %d    %d\n", state_arr[0].address, state_arr[0].line, state_arr[0].column, state_arr[0].file);
                    inc++;
                      
                    if (inc >= allocated_size) {
                        printf("allocationg more matrix space\n");
                        allocated_size = (inc + 1) * 2;
                        state_arr = (ProgramRegisterState *) realloc(state_arr, allocated_size * sizeof(ProgramRegisterState));
                    }
                    if (state_arr == NULL) {
                        free(state_arr);
                        fprintf(stderr, "realloc failed\n");
                        return -1;
                    }
                    append_row_matrix(&state_arr, inc);
                    return 0;
                    break;
                case DW_LNE_set_address:
                    //printf("Setting address\n");
                    uint64_t *addy = (uint64_t *)ptr1;
                    ptr1+=sizeof(addy);
                    printf("%x DW_LNS_set_address (0x%016lx)\n",DW_LNE_set_address, *addy);
                    line_offset = line_offset + (ptr1 - curr);
                    state_arr[0].address = *addy;
                    state_arr[0].op_index = 0;
                    break;
                case DW_LNE_set_discriminator:
                    l_operand = decode_uleb128(&ptr1);
                    state_arr[0].discriminator = l_operand;
                    printf("%x DW_LNE_set_discriminator (%d)\n", *curr, l_operand);
                    line_offset = line_offset + (ptr1 - curr);

                default:
                    break;

            }

        }
        else if (*curr < opcode_base) { // standard opcodes
            switch(*curr) {
                case DW_LNS_set_column:

                    //printf("DW_LNS_set_column: %d\n", *curr);
                    uint64_t col_val = decode_uleb128(&ptr1);
                    //printf("Checking: %d\n", col_val);
                    line_offset = line_offset + (ptr1 - curr);
                    state_arr[0].column = col_val;
                    printf("%x DW_LNS_SET_column (%d)\n", DW_LNS_set_column, col_val);

                    break;
                case DW_LNS_copy:
                    printf("DW_LNS_copy: %d\n", *curr);

                    printf("            0x%016lx     %d    %d    %d\n", state_arr[0].address, state_arr[0].line, state_arr[0].column, state_arr[0].file);

                    line_offset = line_offset + (ptr1 - curr);

                    inc++;
                    append_row_matrix(&state_arr, inc);

                    state_arr[0].discriminator = 0;
                    state_arr[0].basic_block = false;
                    state_arr[0].prologue_end = false;
                    state_arr[0].epilogue_begin = false;

                    break;
                case DW_LNS_advance_pc:

                    // takes a single unsigned leb128 oerand as the operation advance
                    // and modifies the address and op_index
                    l_operand = decode_uleb128(&ptr1);
                    op_advance = (int) l_operand;
                    address_inc = min_ins_len * ((state_arr[0].op_index + op_advance) /
                            max_op_inst);
                    line_offset = line_offset + (ptr1 - curr);

                    printf("%x DW_LNS_advance_pc  (addr += %d, op-index += 0)\n", *curr, address_inc, DW_LNS_advance_pc);
                    state_arr[0].op_index = (state_arr[0].op_index + op_advance) % max_op_inst;

                    state_arr[0].address += address_inc;

                    break;
                case DW_LNS_advance_line:

                    s_operand = decode_sleb128(&ptr1);                    
                    state_arr[0].line += s_operand;
                    line_offset = line_offset + (ptr1 - curr);
                    printf("%x DW_LNS_advance_line %d\n", *curr, s_operand);
                    break;
                case DW_LNS_set_file:
                    l_operand = decode_uleb128(&ptr1);
                    state_arr[0].file = l_operand;
                    printf("%x DW_LNS_set_file %d\n", *curr, l_operand);
                    line_offset = line_offset + (ptr1 - curr);
                    break;
                case DW_LNS_negate_stmt:
                    printf("%x DW_LNS_negate_stmt\n", *curr);
                    state_arr[0].is_stmt = !state_arr[0].is_stmt;
                    line_offset = line_offset + (ptr1 - curr);
                    break;
                case DW_LNS_set_basic_block:
                    printf("%x DW_LNS_set_basic_block \n", *curr);
                    state_arr[0].basic_block = true;
                    line_offset = line_offset + (ptr1 - curr);
                    break;
                case DW_LNS_const_add_pc:

                    // advances the address and op_index registers by the increments 
                    // corresponding to special opcode 255
                    adj_opcode = 255 - opcode_base;
                    op_advance = adj_opcode / line_range;
                    address_inc = min_ins_len * ((state_arr[0].op_index + op_advance) /
                            max_op_inst);

                    state_arr[0].op_index = (state_arr[0].op_index + op_advance) % max_op_inst;

                    printf("%x DW_LNS_const_add_pc (addr += 0x%016x, op-index += 0)\n", *curr, address_inc);
                    line_offset = line_offset + (ptr1 - curr);
                    state_arr[0].address += address_inc;

                    break;
                case DW_LNS_fixed_advance_pc:
                    l_operand = *(uint16_t *)ptr1; 
                    state_arr[0].address = state_arr[0].address + l_operand;
                    state_arr[0].op_index = 0;
                    printf("%x DW_LNS_fixed_advance_pc %d\n", *curr, l_operand);
                    ptr1+=sizeof(l_operand);
                    line_offset = line_offset + (ptr1 - curr);
                    break;
                case DW_LNS_set_prologue_end:
                    printf("%x DW_LNS_fixed_advance_pc \n", *curr);
                    state_arr[0].prologue_end = true;
                    line_offset = line_offset + (ptr1 - curr);
                    break; 
                case DW_LNS_set_epilogue_begin:
                    printf("%x DW_LNS_epilogue_begin \n", *curr);
                    state_arr[0].isa = true;
                    line_offset = line_offset + (ptr1 - curr);
                    break;
                case DW_LNS_set_isa:
                    l_operand = decode_uleb128(&ptr1);
                    state_arr[0].isa = l_operand;
                    printf("%x DW_LNS_set_isa %d\n", *curr, l_operand);
                    line_offset = line_offset + (ptr1 - curr);
                    break;
                default:
                    return 0;
            }


        } else if (*curr >= opcode_base && *curr <= 255) { // special opcodes
            //printf("Special Opcode Number: %d\n", *curr);
            // calculate adjusted opcode and operation advance
            adj_opcode = *curr - opcode_base;
            op_advance = adj_opcode / line_range; 

            address_inc = min_ins_len * ((state_arr[0].op_index + op_advance) / 
                    max_op_inst);

            state_arr[0].op_index = (state_arr[0].op_index + op_advance) % max_op_inst;

            int line_inc = line_base + (adj_opcode % line_range);

            //printf("Adjusted opcode: %d| Operation Advance: %d| Line Increment: %d|\n", adj_opcode, op_advance, line_inc);
            //printf("New Address: 0x%lx += %d | New OpIndex: %d |\n", state_arr[0].address, address_inc, state_arr[0].op_index); 
            // add a signed integer to the line register
            state_arr[0].line = state_arr[0].line + line_inc;
            // modify the operation pointer by incrementing the address and op_index registers
            state_arr[0].address += address_inc;
            // append a row to the matrix using the current values of the state machine reg
            inc++;
            //
            printf("%x address += %d, line += %d, op-index += 0\n", *curr, address_inc, line_inc);

            printf("            0x%016lx     %d    %d    %d\n", state_arr[0].address, state_arr[0].line, state_arr[0].column, state_arr[0].file);
              
            if (inc >= allocated_size) {
                printf("allocating more matrix space\n");
                allocated_size = (inc + 1) * 2;
                state_arr = (ProgramRegisterState *) realloc(state_arr, allocated_size * sizeof(ProgramRegisterState));
            }
            if (state_arr == NULL) {
                fprintf(stderr, "realloc failed\n");
                return -1;
            }
            
            line_offset = line_offset + (ptr1 - curr);
            append_row_matrix(&state_arr, inc);
            // set the basic_blocks register to false
            state_arr[0].basic_block = false;
            // set the prologue_end register to false
            state_arr[0].prologue_end = false;
            // set the epilogue_begin register to false
            state_arr[0].epilogue_begin = false;
            // set the discriminator register to 0
            state_arr[0].discriminator = 0;
            address_inc = 0;
        }

    }
    return 0;
}

Ret debug_init(const char *file_path) {


    char *path = file_path;


    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        printf("failed to open file %s\n", path);
        exit(-1);
    }

    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        printf("failed to get stat\n");
        exit(-1);
    }

    size_t filesize = sb.st_size;

    void *elf_bytes = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (elf_bytes == MAP_FAILED) {
        printf("failed to mmap file\n");
        exit(-1);
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_bytes;
    Elf64_Addr entry = ehdr->e_entry;
    Elf64_Off shoff = ehdr->e_shoff; // section header offset(in bytes) from the elf header
    uint16_t shnum = ehdr->e_shnum; // number of section headers
    uint16_t shstrndx = ehdr->e_shstrndx; //string table section index

    printf("Elf entrypoint: 0x%lx\n", entry);
    printf("Elf section header offset: 0x%lx\n", shoff);
    printf("Number of section headers: %u\n", shnum);

    // Get pontr to section header array
    Elf64_Shdr *shdr_array = (Elf64_Shdr *)((char *) elf_bytes + shoff);
    // Get the string table section header
    Elf64_Shdr *shstrtab = &shdr_array[shstrndx];
    // Get pointer to string table data
    char *strtab = (char *)elf_bytes + shstrtab->sh_offset;

    Elf64_Shdr *sh = get_section(&shdr_array, shnum, ".debug_line", strtab);
    if (sh == NULL) {
        puts("section header is null");
        exit(-1);
    }

    uint8_t * ptr1 = (elf_bytes + sh->sh_offset);
    void * start = ptr1;
    // line number program address start
    uint8_t *lineNumber_ptr = (uint8_t *) (ptr1 + 42);

   /* 
    * in the case that I do use a struct
    DebugLineHeader *data = (DebugLineHeader *) (ptr1);
    */
    DebugLineHeader *data = (DebugLineHeader *) (ptr1);

    // length
    // uint32_t *len = (uint32_t *) (ptr1); 
    // // dwarf version
    // ptr1+=4;
    // uint16_t *version = (uint16_t *) (ptr1);
    // // address size
    // ptr1+=2;
    // uint8_t *addy = (uint8_t *) (ptr1);
    // // seg selector size
    // ptr1+=1;
    // uint8_t *seg_size = (uint8_t *) (ptr1);
    // // header length
    // ptr1+=1;
    // uint32_t *header_len = (uint32_t *) (ptr1);
    // // min instruction length
    // ptr1+=4;
    // uint8_t *min_ins_len = (uint8_t *) ptr1;
    // // max operation per instruction
    // ptr1+=1;
    // uint8_t *max_op_inst = (uint8_t *) ptr1;
    // // default is_st_mt
    // ptr1+=1;
    // uint8_t *def_is_stmt = (uint8_t *) ptr1;
    // // line base
    // ptr1+=1;
    // int8_t *line_base = (int8_t *) ptr1;
    // // line range
    // ptr1+=1;
    // uint8_t *line_range = (uint8_t *) ptr1;
    // // opcode base
    // ptr1+=1;
    // uint8_t *opcode_base = (uint8_t *) ptr1;
    // // standard opcode len
    // ptr1+=1;



    size_t size = (size_t) sh->sh_size;


    puts("Raw dump of debug contents of section .debug_line:");
    puts("");
    printf("   %-30s %u\n", "Length:", data->length);
    printf("   %-30s %u\n", "Dwarf version:", data->version);
    printf("   %-30s %u\n", "Header length:", data->header_length);
    printf("   %-30s %u\n", "Address size (bytes):", data->address_size);
    printf("   %-30s %u\n", "Segment Selector (bytes):", data->segment_selector_size);
    printf("   %-30s %u\n", "Minimun Instruction Length:", data->min_instruction_length);
    printf("   %-30s %u\n", "Maximum Ops per Instruction:", data->max_ops_per_instruction);
    printf("   %-30s %u\n", "Initial values of 'is_stmt':", data->default_is_smt);
    printf("   %-30s %d\n", "Line Base:", data->line_base);
    printf("   %-30s %u\n", "Line Range:", data->line_range);
    printf("   %-30s %u\n", "Opcode Base:", data->opcode_base);

    ptr1 += sizeof(DebugLineHeader);
    uint8_t *std_opcode_len = (uint8_t *) ptr1;
    // directory entry format count
    ptr1 = ptr1 + (data->opcode_base -1);
    uint8_t *dir_ent_fmt_count = ptr1;
    // directory entry format sequence
    ptr1+=1;
    uint8_t *dir_ent_fmt_seq = ptr1;

    // Parse the opcodes
    puts("");
    puts(" Opcodes");

    for(int k = 0; k < data->opcode_base - 1; k++) {
        printf("   Opcode %d has %u args\n", k+1, std_opcode_len[k]);
    }


    printf("   %-30s %u\n", "Directory entry Format:", *dir_ent_fmt_count);
    //uint8_t *ptr3 = dir_ent_fmt_seq;
    uint64_t dct_arr[*dir_ent_fmt_count] = {};
    uint64_t dfc_arr[*dir_ent_fmt_count] = {};
    for (int i = 0; i < *dir_ent_fmt_count; i++) {
        dct_arr[i] = decode_uleb128(&ptr1);
        dfc_arr[i] = decode_uleb128(&ptr1);
        printf("   %x  %x\n", dct_arr[i], dfc_arr[i]);

    }

    uint64_t dc = decode_uleb128(&ptr1);
    printf("Directory count: %d\n", dc); 

    uint8_t *directories = ptr1;

    // now we find the debug_line_str section addr
    sh = get_section(&shdr_array, shnum, ".debug_line_str", strtab);
    if (sh == NULL) {
        puts("debug_line_str section is NULL");
        exit(-1);
    }
    
    uint8_t * db_lstr = (uint8_t *)(elf_bytes + sh->sh_offset);
    //uint8_t * ptr1 = directories;


    for (int j = 0; j < dc; j++) {
        for (int i = 0; i < *dir_ent_fmt_count; i++) {
            switch (dct_arr[i]) {
                case DW_LNCT_path:
                    //printf("Content code is DW_LNCT_path\n");
                    // can only be paired with
                    switch (dfc_arr[i]) {
                        case DW_FORM_line_strp:
                            //printf("Form code is DW_FORM_line_strp\n");

                            uint32_t offset = *(uint32_t *)(ptr1);
                            ptr1 +=4;

                            char *name = (char *)(db_lstr + offset);
                            printf("  offset=0x%x -> \"%s\"\n", offset, name);
                            break;
                        default:    // TODO:
                            break;
                    }
                    break;
                case DW_LNCT_directory_index:
                    printf("Content code is DW_LNCT_directory_index\n");
                    // can only be paired with
                    switch (dfc_arr[i]) {
                        case DW_FORM_udata:
                            //printf("Form code is DW_FORM_udata\n");
                            uint64_t dir_index = decode_uleb128(&ptr1);
                            printf("Dir Index = %d\n", dir_index);
                            //ptr1+=1;
                            break;
                        case DW_FORM_data1: // TODO
                            break;
                        case DW_FORM_data2: // TODO
                            break;
                        default:
                            break;
                    }
                    break;

                default:
                    break;

            }
        }
    }

    // file name entry format count
    uint8_t *file_name_entry_fmt_count = ptr1;
    printf("File Name Entry Format Count: %d\n", *file_name_entry_fmt_count);

    // file name entry format
    uint8_t *file_entry_format = ptr1++;
   
    uint64_t ct_arr[*file_name_entry_fmt_count] = {};
    uint64_t fc_arr[*file_name_entry_fmt_count] = {};

    for (int i = 0; i < *file_name_entry_fmt_count; i++) {
        ct_arr[i] = decode_uleb128(&ptr1);
        fc_arr[i] = decode_uleb128(&ptr1);
        printf("   %x  %x\n", ct_arr[i], fc_arr[i]);
    }

    // file names count
    uint64_t fn_c = decode_uleb128(&ptr1); 
    
    printf("File Name Count: %d\n", fn_c);
    for (int j = 0; j < fn_c; j++) {
        for (int i = 0; i < *file_name_entry_fmt_count; i++) {
            switch (ct_arr[i]) {
                case DW_LNCT_path:
                    printf("Content code is DW_LNCT_path\n");
                    // can only be paired with
                    switch (fc_arr[i]) {
                        case DW_FORM_line_strp:
                            printf("Form code is DW_FORM_line_strp\n");

                            uint32_t offset;
                            memcpy(&offset, ptr1, sizeof(uint32_t));
                            ptr1 +=4;

                            char *name = (char *)(db_lstr + offset);
                            printf("  offset=0x%x -> \"%s\"\n", offset, name);
                            break;
                        default:
                            printf("in here %d %x\n", i, fc_arr[i]);
                            break;
                    }
                    break;
                case DW_LNCT_directory_index:
                    printf("Content code is DW_LNCT_directory_index\n");
                    // can only be paired with
                    switch (fc_arr[i]) {
                        case DW_FORM_udata:
                            printf("Form code is DW_FORM_udata\n");
                            uint64_t dir_index = decode_uleb128(&ptr1);
                            printf("Dir Index = %d\n", dir_index);
                            //ptr1+=1;
                            break;
                        case DW_FORM_data1:
                            printf("Form code is DW_FORM_data1\n");
                            break;
                        case DW_FORM_data2:
                            printf("Form code is DW_FORM_data2\n");
                            break;
                        default:
                            break;
                    }
                    break;

                default:
                    break;
            }
        }
    }

    Ret s = {.start = start, .ptr1 = ptr1, .opcodebase = data->opcode_base, .min_ins_len = data->min_instruction_length, .max_op_inst = data->max_ops_per_instruction, .line_range = data->line_range, .line_base = data->line_base};

    return s;



}


void append_row_matrix(ProgramRegisterState **state_arr, int row_index){
    
    ProgramRegisterState * dummy = *state_arr;
    dummy[row_index].address = dummy[0].address;
    dummy[row_index].op_index = dummy[0].op_index;
    dummy[row_index].file = dummy[0].file;
    dummy[row_index].line = dummy[0].line;
    dummy[row_index].is_stmt = dummy[0].is_stmt;
    dummy[row_index].column = dummy[0].column;
    dummy[row_index].basic_block = dummy[0].basic_block;
    dummy[row_index].end_sequence = dummy[0].end_sequence;
    dummy[row_index].prologue_end = dummy[0].prologue_end;
    dummy[row_index].epilogue_begin = dummy[0].epilogue_begin;
    dummy[row_index].isa = dummy[0].isa;
    dummy[row_index].discriminator = dummy[0].discriminator;

}

void initialize_default_state(ProgramRegisterState **state_arr) {
    ProgramRegisterState * dummy = *state_arr;
    dummy[0].address = 0;
    dummy[0].op_index = 0;
    dummy[0].file = 1;
    dummy[0].line = 1;
    dummy[0].is_stmt = 0;
    dummy[0].column = 0;
    dummy[0].basic_block = false;
    dummy[0].end_sequence = false;
    dummy[0].prologue_end = false;
    dummy[0].epilogue_begin = false;
    dummy[0].isa = 0;
    dummy[0].discriminator = 0;
}


Elf64_Shdr * get_section(Elf64_Shdr **shdr_array, uint16_t sh_num, const char * cmp, char *str_tab) {

    // Now iterate through all section headers
    for (int i = 0; i < sh_num; i++) {
        
        Elf64_Shdr *sh = &(*shdr_array)[i];
        char *name = str_tab + sh->sh_name;

        if (strcmp(name, cmp) == 0) {
            /*
            printf("%s section found\n", cmp);
            printf("    Type: 0x%x\n", sh->sh_type);
            printf("    Offset: 0x%lx\n", sh->sh_offset);
            printf("    Size: 0x%lx\n", sh->sh_size);
            */
            
            if (sh->sh_type == SHT_PROGBITS) {
                return sh;
            }
        }
    }
    return NULL;

}

unsigned char get_next_bytes_in_input() {


}

uint64_t decode_uleb128(uint8_t **ptr){

    uint64_t result = 0;
    int shift = 0;
    uint8_t byte;
    do {
        byte = **ptr;
        (*ptr)++;
        result |= (byte & 0x7f) << shift; // low-order 7 bites of value
        shift += 7;
    } while ((byte & 0x80)); // get high-order bit of byte
    return result;
}


int64_t decode_sleb128(uint8_t **ptr) {

    int64_t result = 0;
    int shift = 0;
    uint8_t byte;

    do {
        byte = **ptr;
        (*ptr)++;
        result |= (int64_t)(byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);

    if ((shift < 64) && (byte & 0x40)) {
        result |= -(1LL << shift);
    }
    return result;
}


































