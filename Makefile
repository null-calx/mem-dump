mem-dump: mem-dump.c logging.c parse-args.c search-path.c elf-parser.c proc-maps-parser.c debugger.c
	gcc -Wall -Wextra -Werror -pedantic -g -o $@ $<
