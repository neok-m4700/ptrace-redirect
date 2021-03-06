#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stddef.h>

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>

static void process_signals(pid_t child);
static int wait_for_open(pid_t child);
static void read_file(pid_t child, char *file);
static void redirect_file(pid_t child, const char *file);

#define NR_CODE __NR_openat
#define RED_ZONE 128

int main(int argc, char **argv)
{
    pid_t child;
    int status;

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <prog> <arg1> ... <argN>\n", argv[0]);
        return 1;
    }

    if ((child = fork()) == 0)
    {
        /* If open syscall, trace */
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_CODE, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = {
            .filter = filter,
            .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        };
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        // To avoid the need for CAP_SYS_ADMIN 
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
        {
            perror("prctl(PR_SET_NO_NEW_PRIVS)");
            return 1;
        }
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
        {
            perror("when setting seccomp filter");
            return 1;
        }
        kill(getpid(), SIGSTOP);
        return execvp(argv[1], argv + 1);
    }
    else
    {
        waitpid(child, &status, 0);
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESECCOMP);
        process_signals(child);
        return 0;
    }
}

static void process_signals(pid_t child)
{
    const char *file_to_redirect = "ONE.txt", *file_to_avoid = "TWO.txt";

    while (1)
    {
        char orig_file[PATH_MAX];

        // Wait for open syscall start 
        if (wait_for_open(child) != 0) break;

        // Find out file and re-direct if it is the target 
        read_file(child, orig_file);
        printf("[Opening %s]\n", orig_file);

        if (strcmp(file_to_avoid, orig_file) == 0)
            redirect_file(child, file_to_redirect);
    }
}

static int wait_for_open(pid_t child)
{
    int status;
    while (1)
    {
        ptrace(PTRACE_CONT, child, 0, 0);
        waitpid(child, &status, 0);
        // printf("[waitpid status: 0x%08x]\n", status);
        // Is it our filter for the open syscall? 
        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)) &&
            ptrace(PTRACE_PEEKUSER, child, sizeof(long) * ORIG_RAX, 0) == NR_CODE)
            return 0;
        if (WIFEXITED(status)) return 1;
    }
}

/*
64 bits registers
-----------------
RAX - register a extended
RBX - register b extended
RCX - register c extended
RDX - register d extended
RBP - register base pointer (start of stack)
RSP - register stack pointer (current location in stack, growing downwards)
RSI - register source index (source for data copies)
RDI - register destination index (destination for data copies)
*/

static void read_file(pid_t child, char *file)
{
    char *child_addr; int i;
    child_addr = (char *) ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RSI, 0);
    do
    {
        long val; char *p;

        val = ptrace(PTRACE_PEEKTEXT, child, child_addr, NULL);
        if (val == -1 && errno != 0)
        { fprintf(stderr, "PTRACE_PEEKTEXT error: %s\n", strerror(errno)); exit(1); }
        child_addr += sizeof(long);

        p = (char *) &val;
        for (i = 0; i < sizeof(long); ++i, ++file)
        { *file = *p++; if (*file == '\0') break; }
    } while (i == sizeof(long));
}

static void redirect_file(pid_t child, const char *file)
{
    char *stack_addr, *file_addr;

    stack_addr = (char *) ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RSP, 0);
    // Move further of red zone and make sure we have space for the file name 
    stack_addr -= RED_ZONE + PATH_MAX;
    file_addr = stack_addr;

    // Write new file in lower part of the stack 
    do
    {
        int i; char val[sizeof(long)];

        for (i = 0; i < sizeof(long); ++i, ++file)
        { val[i] = *file; if (*file == '\0') break; }

        ptrace(PTRACE_POKETEXT, child, stack_addr, *(long *) val);
        stack_addr += sizeof(long);
    } while (*file);

    // Change argument to open 
    ptrace(PTRACE_POKEUSER, child, sizeof(long) * RSI, file_addr);
}
