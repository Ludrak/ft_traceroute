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

// UDP packet structure for traceroute probes
typedef struct  traceroute_packet
{
    // Headers
    struct iphdr   ip;
    struct udphdr  udp;
    // Time Data
    struct timeval time;
    // Data
    uint8_t        data[32];
} __attribute__((packed, aligned(4))) traceroute_packet_t;

// ICMP packet structure for receiving responses
typedef struct  icmp_response_packet
{
    // Headers
    struct iphdr   ip;
    struct icmphdr icmp;
    // Original packet data (for validation)
    uint8_t        original_data[64];
} __attribute__((packed, aligned(4))) icmp_response_packet_t;

// Function declarations
size_t  construct_traceroute_packet(traceroute_packet_t *const pk, const struct iphdr ip_header, const struct udphdr udp_header);
ssize_t construct_packet_from_data(void *const pk, const void *const data, const size_t data_size);

size_t  write_packet_time(traceroute_packet_t *const pk);

int    parse_icmp_response(icmp_response_packet_t pk, char *err_buffer);

struct udphdr construct_traceroute_udphdr(uint16_t src_port, uint16_t dest_port, uint16_t length);
struct iphdr  construct_traceroute_iphdr(const struct sockaddr_in dest_address, uint8_t ttl, uint16_t total_length);

uint16_t checksum(const uint16_t *buff, const size_t size);

// Packet validation and error handling functions
#define VALIDATE_ICMP_ERROR 0
#define VALIDATE_ICMP_SUCCESS 1
#define VALIDATE_ICMP_IGNORED 2
int validate_icmp_response(icmp_response_packet_t *response, uint16_t expected_pid);

int is_destination_reached(icmp_response_packet_t *response);
int is_ttl_exceeded(icmp_response_packet_t *response);

uint32_t get_response_source_ip(icmp_response_packet_t *response);

int validate_packet_structure(void *packet, size_t packet_size, int packet_type);
int handle_network_error(int error_code, char *error_buffer, size_t buffer_size);
int validate_probe_packet(traceroute_packet_t *packet);
const char* get_icmp_annotation(icmp_response_packet_t *pk);

#endif
