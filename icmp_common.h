#ifndef ICMP_COMMON_H
#define ICMP_COMMON_H

#include <stdint.h>
#include <unistd.h>

// Custom header structure for ICMP spoofing
struct custom_icmp_header {
    uint32_t magic;          // Magic number to identify your packets
    uint32_t timestamp;      // Timestamp
    uint8_t ttl;             // Time to live
    uint8_t flags;           // Custom flags
    char x_forwarded_for[16]; // X-Forwarded-For equivalent
    char x_originating_ip[16]; // X-Originating-IP equivalent
    char x_remote_ip[16];    // X-Remote-IP equivalent
    char x_remote_addr[16];  // X-Remote-Addr equivalent
};

// ICMP header structure
struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    union {
        struct {
            uint16_t id;
            uint16_t sequence;
        } echo;
        uint32_t gateway;
        struct {
            uint16_t __unused;
            uint16_t mtu;
        } frag;
    } un;
};

// ICMP types
#define ICMP_ECHOREPLY 0
#define ICMP_ECHO      8

// Checksum function
static inline unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

#endif
#define ICMP_ECHOREPLY 0
#define ICMP_ECHO      8
