CC ?= gcc
CFLAGS ?= -O0 -fsanitize=address,undefined -Wall -Wextra -Wpedantic -Wvla -Wshadow -g

DWARF_DIR = ./dwarf
INC = -I$(DWARF_DIR)

.PHONY: all clean fmt

all: tracer target

tracer: tracer.c $(DWARF_DIR)/dl_parser.o
	$(CC) $(CFLAGS) -lcapstone -lelf $(INC) $^ -o $@

$(DWARF_DIR)/dl_parser.o: $(DWARF_DIR)/dl_parser.c
	$(CC) $(CFLAGS) -c $< -o $@

target: target.c
	$(CC) -g $< -o $@

clean:
	rm -f tracer target $(DWARF_DIR)/*.o

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c
