
The .debug_line section allows to determine the source code file and line number for a given address in memory.
A compilation unit is the result of compile one srouce file `(.c file)` along with all its includes.

    /*
     * Line number information generated for a compilation unit is represented in the .debug_line
     * section of an object file, and optionally also in the .debug_line_str section, and is referenced
     * by a corresponding compilation unit debuggin infomation entry in the .debug_info section.
     */
```bash
gcc -g -c main.c    # produces main.o (1 compilation unit)
gcc -g -c foo.c     # produces foo.o  (1 compilation unit)
gcc -g -c bar.c     # produces bar.o  (1 compilation unit)
gcc -o program main.o foo.o bar.o   # links them together -> produces multiple compilation units within a certain debug section
```

```txt
ELF Binary
├── .text (code from all files)
├── .data
├── .debug_line          ← SECTION
│   ├── Compilation Unit 1 (main.c)
│   │   ├── Header
│   │   ├── File list
│   │   └── Line number program
│   ├── Compilation Unit 2 (foo.c)
│   │   ├── Header
│   │   ├── File list
│   │   └── Line number program
│   └── Compilation Unit 3 (bar.c)
│       ├── Header
│       ├── File list
│       └── Line number program
├── .debug_info          ← SECTION
│   ├── Compilation Unit 1 (main.c)
│   │   └── DIE tree (functions, variables, types)
│   ├── Compilation Unit 2 (foo.c)
│   └── Compilation Unit 3 (bar.c)
└── .debug_abbrev        ← SECTION (shared by all CUs)
```

Dwarf utilizes several encoding system to achieve a compact file-oriented representation.
> There are several encondings which achieve this goal, such as the TAG and attribute abbreviatios or the line number encomding... There are also mutiple  shcmes for eliminating duplicate data or reducing the size of the DWARF debug data associated with a given file. These include COMDAT used to eliminate duplicate function or data definitions.

> If space were not a consideration, the information provided in the `.debug_line` section could be represented as a large matrix, with one row for each instruction in the emitted object code. The matric would have columns for:

| File name  | Line Number  |  Column Number ...|
|------------|--------------|-------------------|
|    ...     |     ...      |       ...         |
|    ...     |     ...      |       ...         |
|    ...     |     ...      |       ...         |

> Such a matrix, however, would be impractically large. We shrink it with two techniques. First, we delete from the matrix each row whose file, line, soruce column and discriminator is identical with that of its predecessos. Any deleted row would never be the beginning of a source statement. 

Instructions with identical file,line,source column are deleted. Hence only the first deleted will be present in the matrix.  

> Second, we design a byte-coded language for a <u>state machine</u> and store a stream of bytes in the object file instead of the matrix. This language can be much more compact than the matrix. To the line number information a consumer must "run" the state machine to generate the matrx for each compilation unit of interest. The concept of an encoded matrix also leaves room for expansion. In the future, columns can be added toe the matrix to encode other things that are related to individual instruction addresses.

After the trimming of the matrix, it is then encoded with some byte-coded(`LEB128 Enconding`) language.


<b>What is a state machine</b>: A finite-state machine is a mathematical model of computation that can be in only one of a finite number of state and changes based on some input. 
 > The hypothetical machine used by a consumer of the line number information to expand the byte-coded instruction stream into a matrix of line number information.

<b>What is a line number program</b>: 
 > A series of byte-coded line number information isntruction representing one compilation unit.

#### State Machine Registers





? Any relation of some sort to (finite) state machine and a finite field
? does dwarf during compilation, include line number from libc[does it have a separate compilation unit for libc files]


```c
typedef struct __attribute__((packed)) {  // ✅ Correct - two underscores
    uint32_t length;
    uint16_t version;
    uint8_t address_size;
    uint8_t segment_selector_size;

    uint32_t header_length;
    uint8_t min_instruction_length; // segment selector
    uint8_t max_ops_per_instruction;
    uint8_t default_is_smt; //
    int8_t line_base;
    uint8_t line_range;
    uint8_t opcode_base;
    // this array specifies the number of LEB128 operands for each of the standard
    // opcodes. The first element of the array corresponds to the opcode whose value
    // 1, and the last element corresponds toe the opcode whose value is opcode_base-1
    // we only have 12 standard opcodes!
    // however by increasing the opcode_base, and adding elements to this array, new
    // standard opcodes can be added, while allowing consumers who do not know about
    // these new opcodes to be able to skip them.j
    uint8_t std_opcode_lengths[12];
    // The remaining fields provide information about the source files used in the 
    // compilation
    //uint8_t directory_entry_format_count;
    // directory_entry_format(sequence of ULEB128 pairs)
    // directories_count (ULEB128)
    // directories (sequence of directory names)
    // file_name_entry_format_count (ubyte)
} DebugLineHeader;
```


? what are the standard opcodes?
? what is LEB128 operands?
