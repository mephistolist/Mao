#ifndef PTRACE_H
#define PTRACE_H

void anti_debug(void);
void check_tracer_pid(void);
void block_ptrace_attaches(void);
void install_seccomp_ptrace_kill(void);

#endif
