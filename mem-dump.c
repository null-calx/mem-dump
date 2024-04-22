#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// should probably increase it, but meh
#define PATH_MAX 100

typedef struct {
    uint64_t     mem_addr;
    uint64_t     mem_oldvalue;
} breakpoint;

typedef struct {
    uint64_t     addr_begin;
    uint64_t     addr_end;
    char         *perms;
    off_t        offset;
    dev_t        dev_major;
    dev_t        dev_minor;
    ino_t        inode;
    char         *pathname;
} procmaps_row;

typedef struct {
    uint8_t      e_ident[16];
    uint16_t     e_type;
    uint16_t     e_machine;
    uint32_t     e_version;
    uint64_t     e_entry;
} elf64_header;

extern char *optarg;
extern int optind;

void
free_procmaps_row(procmaps_row *row)
{
    free(row->perms);
    if (row->pathname)
        free(row->pathname);
    free(row);
}

procmaps_row*
parse_procmaps_line(char *line)
{
    procmaps_row *row = malloc(sizeof(procmaps_row));
    char *perms_token, *pathname_token;

    if (row == NULL)
        return NULL;

    row->addr_begin = strtoull(strtok(line, "-"), NULL, 16);
    row->addr_end   = strtoull(strtok(NULL, " "), NULL, 16);
    perms_token     = strtok(NULL, " ");
    row->offset     = strtoull(strtok(NULL, " "), NULL, 16);
    row->dev_major  = atoi(strtok(NULL, ":"));
    row->dev_minor  = atoi(strtok(NULL, " "));
    row->inode      = atoi(strtok(NULL, " "));
    pathname_token  = strtok(NULL, " \n");

    row->perms = strdup(perms_token);
    if (row->perms == NULL) {
        free(row);
        return NULL;
    }

    if (pathname_token != NULL) {
        row->pathname = strdup(pathname_token);
        if (row->pathname == NULL) {
            free(row->perms);
            free(row);
            return NULL;
        }
    } else {
        row->pathname = NULL;
    }

    return row;
}

void print_info(char *fmt, ...)
{
    va_list p;
    char *msg;

    fflush(NULL);
    msg = NULL;

    va_start(p, fmt);
    if (vasprintf(&msg, fmt, p) >= 0) {
        printf("DBG: %s\n", msg);
        free(msg);
    }
    va_end(p);
}

void
errormsg_and_die(int error_code, char *fmt, ...)
{
    va_list p;
    char *msg;

    fflush(NULL);
    msg = NULL;

    va_start(p, fmt);
    if (vasprintf(&msg, fmt, p) >= 0) {
        fprintf(stderr, "error: %s\n", msg);
        free(msg);
    }
    va_end(p);

    exit(error_code);
}

int
parse_args(int argc, char *argv[], char **outfname)
{
    int opt;

    // "+"  stop as soon as a non-option argument is encountered
    // "o:" option 'o' takes an required argument
    char* optstring = "+o:";

    while ((opt = getopt(argc, argv, optstring)) != -1) {
        switch (opt) {
        case 'o':
            *outfname = optarg;
            break;
        default:
            // won't ever be encountered, i believe
            fprintf(stderr, "?? getopt returned character code 0%o ??\n", opt);
        }
    }

    return optind;
}

/* finds the binary pathname to be given to execve
   given the filename */
void
find_binary(const char *filename, char *pathname, size_t path_len)
{
    size_t filename_len = strlen(filename);
    struct stat statbuf;

    if (filename_len > path_len - 1)
        errormsg_and_die(1, "filename too long");

    // if '/' is in the binary name, we can use the name directly,
    // else we need to look into env[PATH]
    // PSA: having '/' inside the name, does not imply the pathname is
    // absolute, e.g., './mem-dump'
    if (strchr(filename, '/')) {
        strcpy(pathname, filename);
    } else {
        const char *path;
        size_t m, n, len;

        // look for binary in each directory in env[PATH]
        for (path = getenv("PATH"); path && *path; path += m) {
            const char *colon = strchr(path, ':');
            if (colon) {
                // length of current path
                n = colon - path;
                // postion of next path
                m = n + 1;
            } else {
                // last path
                m = n = strlen(path);
            }

            // copy directory names into pathname, only when it's
            // small enough
            if (n == 0) {
                // why would n be zero? i don't get it
                if (!getcwd(pathname, PATH_MAX))
                    continue;
                len = strlen(pathname);
            } else if (n > path_len - 1)
                continue;
            else {
                strncpy(pathname, path, n);
                len = n;
            }

            // ensure ending '/' in directory name
            if (len && pathname[len - 1] != '/')
                pathname[len++] = '/';

            // yeah, just like that
            if (filename_len + len > path_len - 1)
                continue;

            // create complete pathname
            strcpy(pathname + len, filename);

            // check if file exists
            if (stat(pathname, &statbuf) == 0 &&
                // copied comment, idk what they meant
                /* Accept only regular files
                   with some execute bits set.
                   XXX not perfect, might still fail */
                S_ISREG(statbuf.st_mode) &&
                (statbuf.st_mode & 0111))
                break;
        }

        // exhausted all directories in env[PATH]
        if (!path || !*path)
            pathname[0] = '\0';

        if (filename && !*pathname)
            errormsg_and_die(1, "couldn't find executable '%s'", filename);

        if (stat(pathname, &statbuf) < 0)
            errormsg_and_die(1, "cannot stat '%s'", pathname);
    }
}

/* gets binary's entrypoint given the pathname */
uint64_t
binary_entrypoint(const char *pathname)
{
    elf64_header header;

    int binary = open(pathname, O_RDONLY, NULL);
    if (binary < 0)
        errormsg_and_die(1, "cannot open '%s'", pathname);

    if (read(binary, &header, sizeof(header)) < (long int) sizeof(header))
        errormsg_and_die(1, "unable to read binary entrypoint");

    close(binary);

    return header.e_entry;
}

void
parse_mmap(pid_t pid, off_t *loaded_at, procmaps_row ***table_ptr)
{
    procmaps_row **table;
    size_t array_size;
    char *filename, *line;
    size_t i, size;
    FILE *map_file;

    array_size = 32;
    table = calloc(array_size, sizeof(*table));
    if (table == NULL)
        errormsg_and_die(1, "calloc failed");

    i = 0;

    line = NULL;
    size = 0;

    if (asprintf(&filename, "/proc/%d/maps", (int) pid) < 0)
        errormsg_and_die(1, "malloc failed while reading maps files");

    map_file = fopen(filename, "r");
    if (map_file == NULL)
        errormsg_and_die(1, "couldn't open '%s'", filename);

    while (getline(&line, &size, map_file) != -1) {
        if (line != NULL)
            table[i] = parse_procmaps_line(line);
        if (table[i] == NULL)
            errormsg_and_die(1, "couldn't parse maps row");
        ++i;

        if (i == array_size) {
            table = realloc(table, (array_size + 16) * sizeof(*table));
            if (table == NULL)
                errormsg_and_die(1, "realloc failed");
            memset(table + array_size, 0, 16 * sizeof(*table));
            array_size += 16;
        }
        free(line), line = NULL;
    }

    *loaded_at = table[0]->addr_begin;

    fclose(map_file);
    free(filename);

    *table_ptr = table;
}

void
debugger_jumpto(pid_t pid, uint64_t addr)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    regs.rip = addr;
    ptrace(PTRACE_SETREGS, pid, 0, &regs);
}

uint64_t
debugger_readmem(pid_t pid, uint64_t addr)
{
    return ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
}

void
debugger_writemem(pid_t pid, uint64_t addr, uint64_t data)
{
    ptrace(PTRACE_POKEDATA, pid, &addr, &data);
}

void
debugger_dumpmem(FILE *restrict stream, pid_t pid,
                 uint64_t addr_from, uint64_t addr_to,
                 char* pathname, off_t offset, char *perms)
{
    fprintf(stream, "DUMPING MEMORY\n0x%016lx - 0x%016lx\n%s\n0x%06lx\n%s\n",
            addr_from, addr_to,
            pathname, offset, perms);
    uint64_t data;
    if (perms[0] == 'r')
        for (uint64_t addr = addr_from; addr < addr_to; addr += 8) {
            data = debugger_readmem(pid, addr);
            fprintf(stream, "0x%016lx : 0x%016lx\n", addr, data);
        }
    fprintf(stream, "\n");
}

void
debugger_readregs(pid_t pid, struct user_regs_struct *regs)
{
    ptrace(PTRACE_GETREGS, pid, 0, regs);
}

void
debugger_printregs(FILE *restrict stream, pid_t pid)
{
    struct user_regs_struct regs;
    debugger_readregs(pid, &regs);
    fprintf(stream, "DUMPING REGISTERS\n");
    fprintf(stream, "RIP 0x%016llx\n", regs.rip);

    fprintf(stream, "RAX 0x%016llx  ", regs.rax);
    fprintf(stream, "RBX 0x%016llx  ", regs.rbx);
    fprintf(stream, "RCX 0x%016llx  ", regs.rcx);
    fprintf(stream, "RDX 0x%016llx\n", regs.rdx);

    fprintf(stream, "RDI 0x%016llx  ", regs.rdi);
    fprintf(stream, "RSI 0x%016llx  ", regs.rsi);
    fprintf(stream, "RSP 0x%016llx  ", regs.rsp);
    fprintf(stream, "RBP 0x%016llx\n", regs.rbp);

    fprintf(stream, "R8  0x%016llx  ", regs.r8 );
    fprintf(stream, "R9  0x%016llx  ", regs.r9 );
    fprintf(stream, "R10 0x%016llx  ", regs.r10);
    fprintf(stream, "R11 0x%016llx\n", regs.r11);

    fprintf(stream, "R12 0x%016llx  ", regs.r12);
    fprintf(stream, "R13 0x%016llx  ", regs.r13);
    fprintf(stream, "R14 0x%016llx  ", regs.r14);
    fprintf(stream, "R15 0x%016llx\n", regs.r15);

    fprintf(stream, "CS  0x%08llx  ", regs.cs);
    fprintf(stream, "DS  0x%08llx  ", regs.ds);
    fprintf(stream, "ES  0x%08llx  ", regs.es);
    fprintf(stream, "FS  0x%08llx  ", regs.fs);
    fprintf(stream, "GS  0x%08llx  ", regs.gs);
    fprintf(stream, "SS  0x%08llx\n", regs.ss);

    fprintf(stream, "GSB 0x%08llx  ", regs.gs_base);
    fprintf(stream, "FSB 0x%08llx\n", regs.fs_base);

    fprintf(stream, "EFLAGS  0x%04llx ", regs.eflags);
    fprintf(stream, "ORAX 0x%016llx\n", regs.fs_base);
    fprintf(stream, "\n");
}

breakpoint
debugger_create_breakpoint(pid_t pid, uint64_t addr)
{
    uint64_t oldvalue = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    uint64_t newvalue = (oldvalue & ~0xFF) | 0xCC;
    ptrace(PTRACE_POKEDATA, pid, addr, newvalue);
    return (breakpoint) {
        .mem_addr = addr,
        .mem_oldvalue = oldvalue
    };
}

void
debugger_remove_breakpoint(pid_t pid, breakpoint bpt)
{
    ptrace(PTRACE_POKEDATA, pid, bpt.mem_addr, bpt.mem_oldvalue);
}

void
debugger_continue(pid_t pid)
{
    ptrace(PTRACE_CONT, pid, 0, 0);

    waitpid(pid, NULL, 0);
}

int
main(int argc, char *argv[], char *environ[])
{
    char *outfname;           // outfile name
    char pathname[PATH_MAX];  // will contain the actual binary pathname
    int optind;
    uint64_t entrypoint;
    pid_t pid;

    // default outfile name
    outfname = "mem.dump";

    optind = parse_args(argc, argv, &outfname);

    // keep only the subcommand args
    argv += optind;
    argc -= optind;

    // if no subcommand given
    if (argc < 1)
        errormsg_and_die(1, "must have PROG [ARGS]");

    find_binary(argv[0], (char *) pathname, PATH_MAX);
    print_info("pathname: '%s'", pathname);

    entrypoint = binary_entrypoint(pathname);
    print_info("entrypoint: 0x%1lx", entrypoint);

    // time to fork
    pid = fork();
    if (pid < 0)
        errormsg_and_die(1, "couldn't fork");

    if (pid == 0) {
        // inside child

        if (ptrace(PTRACE_TRACEME, 0L, 0L, 0L) < 0)
            errormsg_and_die(1, "unable to ptrace(PTRACE_TRACEME, ...)");

        execve(pathname, argv, environ);
        return 0;
    }

    // inside parent

    FILE *outfile = fopen(outfname, "w");

    int wait_status;
    waitpid(pid, &wait_status, 0);

    procmaps_row **table = NULL;
    off_t loaded_at;
    parse_mmap(pid, &loaded_at, &table);

    uint64_t newentrypoint = loaded_at + entrypoint;

    print_info("pid: %d", pid);

    print_info("new entrypoint: 0x%lx\n", newentrypoint);
    breakpoint bpt = debugger_create_breakpoint(pid, newentrypoint);
    debugger_continue(pid);

    debugger_jumpto(pid, newentrypoint);

    fprintf(outfile, "BINARY: %s\n", pathname);
    fprintf(outfile, "ENTRYPOINT: 0x%016lx\n", newentrypoint);
    fprintf(outfile, "\n");

    debugger_printregs(stdout, pid);
    debugger_printregs(outfile, pid);

    for (size_t i = 0; table[i] != NULL; ++ i) {
        uint64_t addr_begin = table[i]->addr_begin;
        uint64_t addr_end   = table[i]->addr_end;
        off_t offset        = table[i]->offset;
        char *pathname      = table[i]->pathname;
	char *perms         = table[i]->perms;
        debugger_dumpmem(outfile, pid,
                         addr_begin, addr_end,
                         pathname, offset, perms);
        printf("0x%1lx - 0x%1lx: (0x%06lx) %s\n",
               addr_begin, addr_end, offset, pathname);
    }

    (void) bpt;
    // debugger_remove_breakpoint(pid, bpt);
    // debugger_continue(pid);

    print_info("killed child");
    kill(pid, 9);

    fclose(outfile);
    print_info("bye..");
    return 0;
}
