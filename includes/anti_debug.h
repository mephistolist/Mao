#ifndef PTRACE_H
#define PTRACE_H

void anti_debug(void);
void die(const char *msg);
void detect_ld_preload(void);
void check_tracer_pid(void);
void detect_timing_anomalies(void);
void block_ptrace_attaches(void);
void install_seccomp_ptrace_kill(void);
void check_environment(void);
void detect_hardware_breakpoints(void);
void check_memory_integrity(void);

#endif
