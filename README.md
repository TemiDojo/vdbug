# ptracer

A Linux x86-64 debugger built with `ptrace`. It parses DWARF debug info to map instructions back to source lines, disassembles code around the current instruction pointer, and lets you step through a program interactively.

## Features

- Single-step, next (step over calls), finish (step out), and continue
- Breakpoints (up to 16) set by address
- Register display after each step
- Disassembly window showing previous, current, and next instruction with source line mapping
- Before/after memory display for write instructions

## Requirements

- Linux x86-64
- gcc
- [Capstone](https://www.capstone-engine.org/) (`libcapstone-dev`)
- libelf (`libelf-dev`)


## Build

```bash
make
```

This builds two binaries:
- `tracer` — the debugger
- `target` — a sample program to trace

## Usage

```bash
./tracer <path-to-binary>
```

The target binary must be compiled with debug info (`-g`) and without stripping.

Example using the included sample:

```bash
./tracer ./target
```

## Commands

| Key | Action |
|-----|--------|
| `s` | Step — execute one instruction |
| `n` | Next — step over function calls |
| `f` | Finish — run until current function returns |
| `c` | Continue — run until next breakpoint |
| `b` | Set breakpoint — prompts for a hex address |
| `d` | Delete breakpoint — prompts for breakpoint index |
| `q` | Quit — kills the tracee |

## Notes

- Linux only. Relies on `ptrace`, `/proc/pid/maps`, and ELF/DWARF — none of which are available on macOS or Windows.
- The target must be a dynamically linked ELF binary compiled with `-g`.
