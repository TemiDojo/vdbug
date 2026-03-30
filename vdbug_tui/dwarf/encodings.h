#ifndef DWARF_DEFS_H
#define DWARF_DEFS_H

#include <stdint.h>
// Standard opcode encodings
#define DW_LNS_copy 0x01
#define DW_LNS_advance_pc 0x02
#define DW_LNS_advance_line 0x03
#define DW_LNS_set_file 0x04
#define DW_LNS_set_column 0x05
#define DW_LNS_negate_stmt 0x06
#define DW_LNS_set_basic_block 0x07
#define DW_LNS_const_add_pc 0x08
#define DW_LNS_fixed_advance_pc 0x09
#define DW_LNS_set_prologue_end 0x0a
#define DW_LNS_set_epilogue_begin 0x0b
#define DW_LNS_set_isa 0x0c


// Line number extended opcode encodings
#define DW_LNE_end_sequence 0x01
#define DW_LNE_set_address 0x02
// reserved 0x03
#define DW_LNE_set_discriminator 0x04
#define DW_LNE_lo_user 0x80
#define DW_LNE_hi_user 0xff


// Line number header entry format encodings
#define DW_LNCT_path 0x1
#define DW_LNCT_directory_index 0x2
#define DW_LNCT_timestamp 0x3
#define DW_LNCT_size 0x4
#define DW_LNCT_MD5 0x5
#define DW_LNCT_lo_user 0x2000
#define DW_LNCT_hi_user 0x3fff

// Attribute form encodings
#define DW_FORM_addr 0x01 // address
//reserved 0x02
#define DW_FORM_block2 0x03 // block
#define DW_FORM_block4 0x04 // block
#define DW_FORM_data2 0x05 // constant
#define DW_FORM_data4 0x06 // constant
#define DW_FORM_data8 0x07 // constant
#define DW_FORM_string 0x08 // string
#define DW_FORM_block 0x09 // block
#define DW_FORM_block1 0x0a // block
#define DW_FORM_data1 0x0b // constant
#define DW_FORM_flag 0x0c // flag
#define DW_FORM_sdata 0x0d // constant
#define DW_FORM_strp 0x0e // string
#define DW_FORM_udata 0x0f // constant
#define DW_FORM_ref_addr 0x10 // reference
#define DW_FORM_ref1 0x11 // reference
#define DW_FORM_ref2 0x12 // reference
#define DW_FORM_ref4 0x13 // reference
#define DW_FORM_ref8 0x14 // reference
#define DW_FORM_ref_udata 0x15 // reference
#define DW_FORM_indirect 0x16 // (see Section 7.5.3 on page 203)
#define DW_FORM_sec_offset 0x17 // addrptr, lineptr, loclist, loclistptr, macptr, rnglist
                                // rnglistptr, stroffsetptr
#define DW_FORM_exprloc 0x18 // exprloc
#define DW_FORM_flag_present 0x19 // flag
#define DW_FORM_strx 0x1a //string
#define DW_FORM_adrx 0x1b // address
#define DW_FORM_ref_sup4 // reference
#define DW_FORM_strp_sup 0x1d // string
#define DW_FORM_data16 0x1e // constant
#define DW_FORM_line_strp 0x1f // string
#define DW_FORM_ref_sig8 0x20 // reference
#define DW_FORM_implicit_const 0x21 // constant
#define DW_FORM_loclistx 0x22 // loclist
#define DW_FORM_rnglistx 0x23 // rnglist
#define DW_FORM_ref_sup8 0x24 // reference
#define DW_FORM_strx1 0x25 // string
#define DW_FORM_strx2 0x26 // string
#define DW_FORM_strx3 0x27 // string
#define DW_FORM_strx4 0x28 // string
#define DW_FORM_addrx1 0x29 // address
#define DW_FORM_addrx2 0x2a // address
#define DW_FORM_addrx3 0x2b // address
#define DW_FORM_addrx4 0x2c // address


#endif
