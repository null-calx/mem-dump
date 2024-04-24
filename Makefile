CFLAGS=-Wall -Wextra -Wextra -pedantic
LIBS=

ifeq ($(DEBUG), 1)
  OPTIMIZATION_FLAGS=-g
else
  OPTIMIZATION_FLAGS=-O2
endif

mem-dump: main.c logging.c parse-args.c search-path.c elf-parser.c proc-maps-parser.c debugger.c
	gcc $(CFLAGS) $(OPTIMIZATION_FLAGS) -o $@ $< $(LIBS)
