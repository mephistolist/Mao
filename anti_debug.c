#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <pthread.h>
#include "includes/anti_debug.h"

// Kill immediately
static void die(const char *msg) {
    fprintf(stderr, "[anti_debug] %s\n", msg);
    kill(getpid(), SIGKILL);
}

// Step 1: Check if already being traced
static void check_tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer_pid = atoi(line + 10);
            fclose(f);
            if (tracer_pid != 0) {
                die("Tracer detected (TracerPid)");
            }
            return;
        }
    }
    fclose(f);
}

// Step 2: Prevent future ptrace attaches
static void block_ptrace_attaches(void) {
    prctl(PR_SET_DUMPABLE, 0);
    prctl(PR_SET_PTRACER, -1);
}

// Step 3: Install a Seccomp BPF filter to kill on ptrace syscall
static void install_seccomp_ptrace_kill(void) {
    struct sock_filter filter[] = {
        // Load syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        // If syscall == ptrace -> kill
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        // Else → allow
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        perror("prctl(NO_NEW_PRIVS)");
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
        perror("prctl(SECCOMP)");
} 

static void detect_ld_preload(void) {
    char *ld_preload = getenv("LD_PRELOAD");
    if (ld_preload != NULL && *ld_preload != '\0') {
        die("LD_PRELOAD detected - likely injection attempt");
    }
}

static void check_environment(void) {
    // Check for common debugger environment variables
    const char *debug_vars[] = {
        "LD_DEBUG", "LD_DEBUG_OUTPUT", "LD_AUDIT", "LD_PROFILE",
        "LD_ORIGIN_PATH", "LD_SHOW_AUXV", "LD_TRACE_LOADED_OBJECTS",
        "LD_WARN", "LD_VERBOSE", "LD_BIND_NOW", "LD_DYNAMIC_WEAK"
    };
    
    for (size_t i = 0; i < sizeof(debug_vars)/sizeof(debug_vars[0]); i++) {
        if (getenv(debug_vars[i]) != NULL) {
            die("Debug environment variable detected");
        }
    }
    
    // Check for unusual TTY (debuggers often run in different terminals)
    char *tty = ttyname(0);
    if (tty != NULL && strstr(tty, "pts") == NULL) {
        die("Unusual TTY detected - possible debugging environment");
    }
} 

// Timing attack detection 
static void detect_timing_anomalies(void) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    // Do some meaningless but timing-sensitive operations
    volatile unsigned long long counter = 0;
    for (int i = 0; i < 1000000; i++) {
        counter += i * 0xDEADBEEF;
    }
    (void)counter;
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    long long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                          (end.tv_nsec - start.tv_nsec);
    
    // If execution took too long (debugger overhead), die
    if (elapsed_ns > 50000000) { // 50ms threshold
        die("Timing anomaly detected - likely under debugger");
    }
} 

static void breakpoint_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)sig;
    (void)info;
    (void)ucontext;
    die("Hardware breakpoint detected");
}

static void detect_hardware_breakpoints(void) {
    struct sigaction sa;
    sa.sa_sigaction = breakpoint_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    
    sigaction(SIGTRAP, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}

static void check_memory_integrity(void) {
    // Use GCC attributes to get function addresses in a standard-compliant way
    uintptr_t return_addr = (uintptr_t)__builtin_return_address(0);
    unsigned char *code_start = (unsigned char *)(return_addr - 128);
    unsigned char checksum = 0;
    
    // Check a small region around the return address
    for (int i = 0; i < 64; i++) {
        checksum ^= code_start[i];
    }
    
    // This would need to be pre-computed during build
    // For now, just ensure it's not a obvious breakpoint pattern
    if (checksum == 0xCC) { // Single byte breakpoint
        die("Breakpoint detected in code");
    }
}

// Call this once early in the program
void anti_debug(void) {
#ifdef __linux__
    check_tracer_pid();
    detect_ld_preload();
    check_environment();
    block_ptrace_attaches();
    detect_timing_anomalies();
    detect_hardware_breakpoints();
    check_memory_integrity();
    install_seccomp_ptrace_kill();
#endif
}
