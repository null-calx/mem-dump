#include "logging.c"
#include "parse-args.c"
#include "search-path.c"
#include "elf-parser.c"
#include "proc-maps-parser.c"
#include "debugger.c"

#include <signal.h>

#define PATH_MAX 100

int
main(int argc, char *argv[], char *envp[])
{
    char *outfname;
    int optind;
    char pathname[PATH_MAX];
    uint64_t entrypoint;

    pid_t pid;
    FILE *outfile;

    procmaps_table *table;
    uint64_t newentrypoint;

    outfname = "mem.dump";
    optind = parse_args(argc, argv, &outfname);

    argv += optind;
    argc -= optind;

    if (argc < 1)
        die(1, "must have PROG [ARGS]");

    find_binary(argv[0], (char *) pathname, PATH_MAX);
    info("found binary: '%s'", pathname);

    entrypoint = binary_entrypoint(pathname);
    info("found entrypoint: 0x%016lx", entrypoint);

    pid = fork();
    if (pid < 0)
        die(1, "couldn't fork");

    if (pid == 0) {
        // child process
        if (debugger_trace_me())
            die(1, "unable to call ptrace(PTRACE_TRACEME, ...)");
        execve(pathname, argv, envp);
        return 0;
    }

    // parent process
    info("child pid: %d", pid);

    debugger_prepared(pid);
    table = parse_procmaps(pid);

    newentrypoint = loading_offset(table) + entrypoint;
    info("new entrypoint: 0x%016lx", newentrypoint);

    debugger_continue_until(pid, newentrypoint);

    outfile = fopen(outfname, "w");
    debugger_dump_registers(pid, outfile);
    debugger_dump_memory(pid, table, outfile);
    fclose(outfile);
    info("dumped to file: %s", outfname);

    kill(pid, 9);
    info("killed child");

    destroy_procmaps_table(table);
    info("bye..");

    return 0;
}
