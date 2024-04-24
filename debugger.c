#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

long
debugger_trace_me()
{
    return ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
}

void
debugger_continue_until(pid_t pid, uint64_t addr)
{
    struct user_regs_struct regs;
    uint64_t oldvalue, newvalue;

    oldvalue = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);

    newvalue = (oldvalue & ~0xFF) | 0xCC;
    ptrace(PTRACE_POKEDATA, pid, addr, newvalue);

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, NULL, 0);

    ptrace(PTRACE_POKEDATA, pid, addr, oldvalue);

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    regs.rip = addr;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}

void
debugger_dump_registers(pid_t pid, FILE *stream)
{
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

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

void
debugger_dump_memory(pid_t pid, procmaps_table *table, FILE *stream)
{
    for (size_t i = 0; table[i] != NULL; ++ i) {
        fprintf(stream, "DUMPING MEMORY\n");
        fprintf(stream, "ADDR 0x%016lx - 0x%016lx\n", table[i]->addr_begin, table[i]->addr_end);
        fprintf(stream, "PATH %s\n", table[i]->pathname);
        fprintf(stream, "OFF  0x%06lx\n", table[i]->offset);
        fprintf(stream, "PERM %s\n", table[i]->perms);

        if (table[i]->perms[0] == 'r')
            for (uint64_t addr = table[i]->addr_begin; addr < table[i]->addr_end; addr += 8) {
                fprintf(stream, "%016lx\n", ptrace(PTRACE_PEEKDATA, pid, addr, NULL));
            }

        fprintf(stream, "\n");
    }
}

void
debugger_prepared(pid_t pid)
{
    waitpid(pid, NULL, 0);
}
