#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include "encodings.h"
#include "inc/dl_parser.h"

// source: https://wiki.osdev.org/DWARF#Relocation
/* Source:
 * The content of a the debug sections is broken down by compilation units
 *
*/

int dump_dl(const char *filepath, Matrix *m) {

    char *path = strdup(filepath);

    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        //printf("failed to open file %s\n", path);
        exit(-1);
    }

    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        //printf("failed to get stat\n");
        exit(-1);
    }

    size_t filesize = sb.st_size;

    void *elf_bytes = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (elf_bytes == MAP_FAILED) {
        //printf("failed to mmap file\n");
        exit(-1);
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_bytes;
    //Elf64_Addr entry = ehdr->e_entry;
    Elf64_Off shoff = ehdr->e_shoff; // section header offset(in bytes) from the elf header
    uint16_t shnum = ehdr->e_shnum; // number of section headers
    uint16_t shstrndx = ehdr->e_shstrndx; //string table section index

    //printf("Elf entrypoint: 0x%lx\n", entry);
    //printf("Elf section header offset: 0x%lx\n", shoff);
    //printf("Number of section headers: %u\n", shnum);

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

    uint8_t * ptr1 = (uint8_t *)((uintptr_t)elf_bytes + (uintptr_t)sh->sh_offset);
    void * start = ptr1;
    // line number program address start

    DebugLineHeader *data = (DebugLineHeader *) (ptr1);




    //puts("Raw dump of debug contents of section .debug_line:");
    //puts("");
    //printf("   %-30s %u\n", "Length:", data->length);
    //printf("   %-30s %u\n", "Dwarf version:", data->version);
    //printf("   %-30s %u\n", "Header length:", data->header_length);
    //printf("   %-30s %u\n", "Address size (bytes):", data->address_size);
    //printf("   %-30s %u\n", "Segment Selector (bytes):", data->segment_selector_size);
    //printf("   %-30s %u\n", "Minimun Instruction Length:", data->min_instruction_length);
    //printf("   %-30s %u\n", "Maximum Ops per Instruction:", data->max_ops_per_instruction);
    //printf("   %-30s %u\n", "Initial values of 'is_stmt':", data->default_is_smt);
    //printf("   %-30s %d\n", "Line Base:", data->line_base);
    //printf("   %-30s %u\n", "Line Range:", data->line_range);
    //printf("   %-30s %u\n", "Opcode Base:", data->opcode_base);

    ptr1 += sizeof(DebugLineHeader);
    //uint8_t *std_opcode_len = (uint8_t *) ptr1;
    // directory entry format count
    ptr1 = ptr1 + (data->opcode_base -1);
    uint8_t *dir_ent_fmt_count = ptr1;
    // directory entry format sequence
    ptr1+=1;

    // Parse the opcodes
    //puts("");
    //puts(" Opcodes");

    for(int k = 0; k < data->opcode_base - 1; k++) {
        //printf("   Opcode %d has %u args\n", k+1, std_opcode_len[k]);
    }


    //printf("   %-30s %u\n", "Directory entry Format:", *dir_ent_fmt_count);

    uint64_t *dct_arr = calloc(*dir_ent_fmt_count, sizeof(uint64_t));
    uint64_t *dfc_arr = calloc(*dir_ent_fmt_count, sizeof(uint64_t));

    if (!dct_arr || !dfc_arr) {
        perror("Failed to allocate directory/file arrays");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < *dir_ent_fmt_count; i++) {
        dct_arr[i] = decode_uleb128(&ptr1);
        dfc_arr[i] = decode_uleb128(&ptr1);
        //printf("   %lx  %lx\n", dct_arr[i], dfc_arr[i]);

    }

    uint64_t dc = decode_uleb128(&ptr1);
    //printf("Directory count: %ld\n", dc); 


    // now we find the debug_line_str section addr
    sh = get_section(&shdr_array, shnum, ".debug_line_str", strtab);
    if (sh == NULL) {
        puts("debug_line_str section is NULL");
        exit(-1);
    }
    
    //uint8_t * db_lstr = (uint8_t *)((uintptr_t)elf_bytes + (uintptr_t)sh->sh_offset);
    //uint8_t * ptr1 = directories;


    for (uint64_t j = 0; j < dc; j++) {
        for (int i = 0; i < *dir_ent_fmt_count; i++) {
            switch (dct_arr[i]) {
                case DW_LNCT_path:
                    ////printf("Content code is DW_LNCT_path\n");
                    // can only be paired with
                    switch (dfc_arr[i]) {
                        case DW_FORM_line_strp:
                            ////printf("Form code is DW_FORM_line_strp\n");

                            uint32_t offset;
                            memcpy(&offset, ptr1, sizeof(uint32_t));
                            ptr1 +=4;

                            //char *name = (char *)(db_lstr + offset);
                            //printf("  offset=0x%x -> \"%s\"\n", offset, name);
                            break;
                        default:    // TODO:
                            break;
                    }
                    break;
                case DW_LNCT_directory_index:
                    //printf("Content code is DW_LNCT_directory_index\n");
                    // can only be paired with
                    switch (dfc_arr[i]) {
                        case DW_FORM_udata:
                            ////printf("Form code is DW_FORM_udata\n");
                            //uint64_t dir_index = decode_uleb128(&ptr1);
                            decode_uleb128(&ptr1);
                            //printf("Dir Index = %ld\n", dir_index);
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
    //printf("File Name Entry Format Count: %d\n", *file_name_entry_fmt_count);

    // file name entry format
    ptr1++;

    uint64_t *ct_arr = calloc(*file_name_entry_fmt_count, sizeof(uint64_t));
    uint64_t *fc_arr = calloc(*file_name_entry_fmt_count, sizeof(uint64_t));

    if (!ct_arr || !fc_arr) {
        perror("Failed to allocate directory/file arrays");
        free(ct_arr);
        free(fc_arr);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < *file_name_entry_fmt_count; i++) {
        ct_arr[i] = decode_uleb128(&ptr1);
        fc_arr[i] = decode_uleb128(&ptr1);
        //printf("   %lx  %lx\n", ct_arr[i], fc_arr[i]);
    }

    // file names count
    uint64_t fn_c = decode_uleb128(&ptr1); 
    
    //printf("File Name Count: %ld\n", fn_c);
    for (uint64_t j = 0; j < fn_c; j++) {
        for (int i = 0; i < *file_name_entry_fmt_count; i++) {
            switch (ct_arr[i]) {
                case DW_LNCT_path:
                    //printf("Content code is DW_LNCT_path\n");
                    // can only be paired with
                    switch (fc_arr[i]) {
                        case DW_FORM_line_strp:
                            //printf("Form code is DW_FORM_line_strp\n");

                            uint32_t offset;
                            memcpy(&offset, ptr1, sizeof(uint32_t));
                            ptr1 +=4;

                            //char *name = (char *)(db_lstr + offset);
                            //printf("  offset=0x%x -> \"%s\"\n", offset, name);
                            break;
                        default:
                            puts("Invalid Content code");
                            exit(-1);
                            break;
                    }
                    break;
                case DW_LNCT_directory_index:
                    //printf("Content code is DW_LNCT_directory_index\n");
                    // can only be paired with
                    switch (fc_arr[i]) {
                        case DW_FORM_udata:
                            //printf("Form code is DW_FORM_udata\n");
                            //uint64_t dir_index = decode_uleb128(&ptr1);
                            decode_uleb128(&ptr1);
                            //printf("Dir Index = %ld\n", dir_index);
                            //ptr1+=1;
                            break;
                        case DW_FORM_data1:
                            //printf("Form code is DW_FORM_data1\n");
                            break;
                        case DW_FORM_data2:
                            //printf("Form code is DW_FORM_data2\n");
                            break;
                        default:
                            puts("Invalid Form code");
                            exit(-1);
                            break;
                    }
                    break;

                default:
                    break;
            }
        }
    }


    ProgramRegisterState state_arr = {0};
    // initialize default program register state
    initialize_default_state(&state_arr);

    // Line Number Program
    uint8_t * curr;
    uint64_t l_operand;
    int64_t s_operand;
    int adj_opcode;
    int op_advance;
    uint64_t address_inc;

    uint64_t line_offset = (uintptr_t)ptr1 - (uintptr_t)start;

    //printf("\n\n");


    while ((curr = ptr1++)) {
        //printf("0x%08lx: ", line_offset); 
        // special opcode ranges from 13 to 255
        // the lower bound may increase if one adds new standard opcodes. Thus,26
        // the opcode_base field of the line number program header gives the value of the first27
        // special opcode.
        if (*curr == 0x00) {
            // how many bytes ex opcode spans
            //int span = *ptr1++;
            ptr1++;

            //printf("opcode spans %d bytes\n", span);
            uint8_t ex_opcode = *ptr1++;
            switch(ex_opcode) {
                case DW_LNE_end_sequence: 
                    state_arr.end_sequence = true;
                    ////printf("Appending to row/ End sequence \n");
                    //printf("%x DW_LNE_end_sequence\n", *curr); 
                    //printf("            0x%016lx     %ld    %ld    %ld\n", state_arr.address, state_arr.line, state_arr.column, state_arr.file);

                    add_row(m, state_arr);
                    free(ct_arr);
                    free(fc_arr);
                    free(dct_arr);
                    free(dfc_arr);
                    free(path);
                    return 0;
                    break;
                case DW_LNE_set_address:
                    ////printf("Setting address\n");
                    //uint64_t *addy = (uint64_t *)ptr1;
                    uint64_t addy;
                    memcpy(&addy, ptr1, sizeof(uint64_t));
                    ptr1+=sizeof(addy);
                    //printf("%x DW_LNS_set_address (0x%016lx)\n",DW_LNE_set_address, addy);
                    line_offset = line_offset + (ptr1 - curr);
                    state_arr.address = addy;
                    state_arr.op_index = 0;
                    break;
                case DW_LNE_set_discriminator:
                    l_operand = decode_uleb128(&ptr1);
                    state_arr.discriminator = l_operand;
                    //printf("%x DW_LNE_set_discriminator (%ld)\n", *curr, l_operand);
                    line_offset = line_offset + (ptr1 - curr);
                    break;                    
                default:
                    puts("Invalid opcode");
                    exit(-1);
                    break;

            }

        }
        else if (*curr < data->opcode_base) { // standard opcodes
            switch(*curr) {
                case DW_LNS_set_column:

                    ////printf("DW_LNS_set_column: %d\n", *curr);
                    uint64_t col_val = decode_uleb128(&ptr1);
                    ////printf("Checking: %d\n", col_val);
                    line_offset = line_offset + (ptr1 - curr);
                    state_arr.column = col_val;
                    //printf("%x DW_LNS_SET_column (%ld)\n", DW_LNS_set_column, col_val);

                    break;
                case DW_LNS_copy:
                    //printf("DW_LNS_copy: %d\n", *curr);

                    //printf("            0x%016lx     %ld    %ld    %ld\n", state_arr.address, state_arr.line, state_arr.column, state_arr.file);

                    line_offset = line_offset + (ptr1 - curr);

                    // append_row_matrix(&state_arr, inc);
                    add_row(m, state_arr);
                    state_arr.discriminator = 0;
                    state_arr.basic_block = false;
                    state_arr.prologue_end = false;
                    state_arr.epilogue_begin = false;

                    break;
                case DW_LNS_advance_pc:

                    // takes a single unsigned leb128 oerand as the operation advance
                    // and modifies the address and op_index
                    l_operand = decode_uleb128(&ptr1);
                    op_advance = (int) l_operand;
                    address_inc = data->min_instruction_length * ((state_arr.op_index + op_advance) /
                            data->max_ops_per_instruction);
                    line_offset = line_offset + (ptr1 - curr);

                    //printf("%x DW_LNS_advance_pc  (addr += %ld, op-index += 0)\n", *curr, address_inc );
                    state_arr.op_index = (state_arr.op_index + op_advance) % data->max_ops_per_instruction;

                    state_arr.address += address_inc;

                    break;
                case DW_LNS_advance_line:

                    s_operand = decode_sleb128(&ptr1);                    
                    state_arr.line += s_operand;
                    line_offset = line_offset + (ptr1 - curr);
                    //printf("%x DW_LNS_advance_line %ld\n", *curr, s_operand);
                    break;
                case DW_LNS_set_file:
                    l_operand = decode_uleb128(&ptr1);
                    state_arr.file = l_operand;
                    //printf("%x DW_LNS_set_file %ld\n", *curr, l_operand);
                    line_offset = line_offset + (ptr1 - curr);
                    break;
                case DW_LNS_negate_stmt:
                    //printf("%x DW_LNS_negate_stmt\n", *curr);
                    state_arr.is_stmt = !state_arr.is_stmt;
                    line_offset = line_offset + (ptr1 - curr);
                    break;
                case DW_LNS_set_basic_block:
                    //printf("%x DW_LNS_set_basic_block \n", *curr);
                    state_arr.basic_block = true;
                    line_offset = line_offset + (ptr1 - curr);
                    break;
                case DW_LNS_const_add_pc:

                    // advances the address and op_index registers by the increments 
                    // corresponding to special opcode 255
                    adj_opcode = 255 - data->opcode_base;
                    op_advance = adj_opcode / data->line_range;
                    address_inc = data->min_instruction_length * ((state_arr.op_index + op_advance) /
                            data->max_ops_per_instruction);

                    state_arr.op_index = (state_arr.op_index + op_advance) % data->max_ops_per_instruction;

                    //printf("%x DW_LNS_const_add_pc (addr += 0x%016lx, op-index += 0)\n", *curr, address_inc);
                    line_offset = line_offset + (ptr1 - curr);
                    state_arr.address += address_inc;

                    break;
                case DW_LNS_fixed_advance_pc:
                    l_operand = *(uint16_t *)ptr1; 
                    state_arr.address = state_arr.address + l_operand;
                    state_arr.op_index = 0;
                    //printf("%x DW_LNS_fixed_advance_pc %ld\n", *curr, l_operand);
                    ptr1+=sizeof(l_operand);
                    line_offset = line_offset + (ptr1 - curr);
                    break;
                case DW_LNS_set_prologue_end:
                    //printf("%x DW_LNS_fixed_advance_pc \n", *curr);
                    state_arr.prologue_end = true;
                    line_offset = line_offset + (ptr1 - curr);
                    break; 
                case DW_LNS_set_epilogue_begin:
                    //printf("%x DW_LNS_epilogue_begin \n", *curr);
                    state_arr.isa = true;
                    line_offset = line_offset + (ptr1 - curr);
                    break;
                case DW_LNS_set_isa:
                    l_operand = decode_uleb128(&ptr1);
                    state_arr.isa = l_operand;
                    //printf("%x DW_LNS_set_isa %ld\n", *curr, l_operand);
                    line_offset = line_offset + (ptr1 - curr);
                    break;
                default:
                    puts("Invalid opcode 2");
                    exit(-1);
                    break;
            }


        } else if (*curr >= data->opcode_base) { // special opcodes
            ////printf("Special Opcode Number: %d\n", *curr);
            // calculate adjusted opcode and operation advance
            adj_opcode = *curr - data->opcode_base;
            op_advance = adj_opcode / data->line_range; 

            address_inc = data->min_instruction_length * ((state_arr.op_index + op_advance) / 
                    data->max_ops_per_instruction);

            state_arr.op_index = (state_arr.op_index + op_advance) % data->max_ops_per_instruction;

            int line_inc = data->line_base + (adj_opcode % data->line_range);

            ////printf("Adjusted opcode: %d| Operation Advance: %d| Line Increment: %d|\n", adj_opcode, op_advance, line_inc);
            ////printf("New Address: 0x%lx += %d | New OpIndex: %d |\n", state_arr.address, address_inc, state_arr.op_index); 
            // add a signed integer to the line register
            state_arr.line = state_arr.line + line_inc;
            // modify the operation pointer by incrementing the address and op_index registers
            state_arr.address += address_inc;
            // append a row to the matrix using the current values of the state machine reg
            //printf("%x address += %ld, line += %d, op-index += 0\n", *curr, address_inc, line_inc);

            //printf("            0x%016lx     %ld    %ld    %ld\n", state_arr.address, state_arr.line, state_arr.column, state_arr.file);
              
            
            line_offset = line_offset + (ptr1 - curr);
            //append_row_matrix(&state_arr, inc);
            add_row(m, state_arr);
            // set the basic_blocks register to false
            state_arr.basic_block = false;
            // set the prologue_end register to false
            state_arr.prologue_end = false;
            // set the epilogue_begin register to false
            state_arr.epilogue_begin = false;
            // set the discriminator register to 0
            state_arr.discriminator = 0;
            address_inc = 0;
        }

    }
    free(path);
    free(dct_arr);
    free(dfc_arr);
    free(ct_arr);
    free(fc_arr);

    return 0;
}




void add_row(Matrix *m, ProgramRegisterState dummy) {
    
    if (m->count >= m->capacity) {
        m->capacity = (m->capacity == 0) ? 64 : m->capacity * 2;
        ProgramRegisterState **temp = realloc(m->arr, m->capacity * sizeof(ProgramRegisterState *));
        if (!temp) {
            perror("Matrix realloc failed");
            exit(EXIT_FAILURE);
        }
        m->arr = temp;
    }

    ProgramRegisterState *temp = malloc(sizeof(ProgramRegisterState));
    if (temp == NULL) {
        perror("Row malloc failed");
        exit(EXIT_FAILURE);
    }

    temp->address = dummy.address;
    temp->op_index = dummy.op_index;
    temp->file = dummy.file;
    temp->line = dummy.line;
    temp->is_stmt = dummy.is_stmt;
    temp->column = dummy.column;
    temp->basic_block = dummy.basic_block;
    temp->end_sequence = dummy.end_sequence;
    temp->prologue_end = dummy.prologue_end;
    temp->epilogue_begin = dummy.epilogue_begin;
    temp->isa = dummy.isa;
    temp->discriminator = dummy.discriminator;

    m->arr[m->count] = temp;

    // 4. Increment the row count
    m->count++;
}

Matrix * initialize_matrix() {
    Matrix *m = malloc(sizeof(Matrix));
    m->count = 0;
    m->capacity = 8;
    m->arr = calloc(m->capacity, sizeof(ProgramRegisterState));
    return m;

}

void initialize_default_state(ProgramRegisterState *state_arr) {
    (*state_arr).address = 0;
    (*state_arr).op_index = 0;
    (*state_arr).file = 1;
    (*state_arr).line = 1;
    (*state_arr).is_stmt = 0;
    (*state_arr).column = 0;
    (*state_arr).basic_block = false;
    (*state_arr).end_sequence = false;
    (*state_arr).prologue_end = false;
    (*state_arr).epilogue_begin = false;
    (*state_arr).isa = 0;
    (*state_arr).discriminator = 0;
}


Elf64_Shdr * get_section(Elf64_Shdr **shdr_array, uint16_t sh_num, const char * cmp, char *str_tab) {

    // Now iterate through all section headers
    for (int i = 0; i < sh_num; i++) {
        
        Elf64_Shdr *sh = &(*shdr_array)[i];
        char *name = str_tab + sh->sh_name;

        if (strcmp(name, cmp) == 0) {
            /*
            //printf("%s section found\n", cmp);
            //printf("    Type: 0x%x\n", sh->sh_type);
            //printf("    Offset: 0x%lx\n", sh->sh_offset);
            //printf("    Size: 0x%lx\n", sh->sh_size);
            */
            
            if (sh->sh_type == SHT_PROGBITS) {
                return sh;
            }
        }
    }
    return NULL;

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


































