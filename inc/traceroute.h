#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <sys/select.h>

#include "time_utils.h"
#include "net_utils.h"
#include "print_utils.h"
#include "packet.h"
#include "options.h"

#define MAX_HOPS 30
#define BASE_PORT 33434
#define PROBES_PER_HOP 3
#define TIMEOUT_SEC 1
#define TIMEOUT_USEC 60000 // 60ms

typedef struct s_hop_result
{
    uint8_t hop_number;
    string_hostname_t ip_addr;
    string_hostname_t hostname;
    time_t rtt[PROBES_PER_HOP];
    uint8_t received_probes;
    uint8_t timeout_probes;
    uint8_t is_destination;
}              hop_result_t;

typedef struct s_traceroute_stats
{
    string_hostname_t  dest_addr;
    string_hostname_t  dest_hostname;
    
    uint16_t   total_hops;
    uint16_t   max_hops;
    uint16_t   current_hop;
    
    hop_result_t  hops[MAX_HOPS];
}              traceroute_stats_t;

typedef struct  s_traceroute_ctx
{
    socket_t    udp_socket;
    socket_t    icmp_socket;
    struct sockaddr_in *dest_sockaddr;

    uint16_t    current_port;
    uint16_t    current_ttl;
    uint16_t    source_port;

    traceroute_stats_t  stats;
}               traceroute_ctx_t;

extern traceroute_ctx_t ctx;

int  init_ctx(const string_hostname_t hostname, int options);
int  ctx_add_hop_result(const uint8_t hop, const string_hostname_t ip, const time_t rtt, const uint8_t probe_num);
void destroy_ctx();

#endif //TRACEROUTE_H
