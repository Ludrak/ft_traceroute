#ifndef PACKET_H
#define PACKET_H

#include <netinet/in.h>
#include <netdb.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <memory.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>

#define MAX_PACKET_SIZE  1024

typedef uint8_t  packet_t[MAX_PACKET_SIZE];

typedef struct  icmp_response_packet
{
    // Headers
    struct iphdr   ip;
    struct icmphdr icmp;
    // Original packet data (for validation)
    uint8_t        original_data[64];
} __attribute__((packed, aligned(4))) icmp_response_packet_t;

// Packet validation and error handling functions
#define VALIDATE_ICMP_ERROR 0
#define VALIDATE_ICMP_SUCCESS 1
#define VALIDATE_ICMP_IGNORED 2
int validate_icmp_response(icmp_response_packet_t *response, uint16_t expected_pid, uint16_t hop_count);

int is_destination_reached(icmp_response_packet_t *response);
int is_ttl_exceeded(icmp_response_packet_t *response);

uint32_t get_response_source_ip(icmp_response_packet_t *response);

int validate_packet_structure(void *packet, size_t packet_size, int packet_type);
int handle_network_error(int error_code, char *error_buffer, size_t buffer_size);
const char* get_icmp_annotation(icmp_response_packet_t *pk);

#endif
