#include "traceroute.h"
#include "time_utils.h"
#include <math.h>
#include <stdarg.h>

// Debug logging with timestamps
void debug_log(const char *format, ...) {
    if (getenv("TRACEROUTE_DEBUG")) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        printf("[DEBUG %ld.%06ld] ", tv.tv_sec, tv.tv_usec);

        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
        printf("\n");
    }
}

traceroute_ctx_t ctx;

void on_interrupt(int sig)
{
    printf("\n");
    destroy_ctx();
    exit(sig);
}

// REMOVED: construct_probe_packet() - unused dead code

int send_probe_packet(uint8_t ttl, uint16_t dest_port)
{
    debug_log("Sending probe: TTL=%d, dest_port=%d", ttl, dest_port);

    // Create raw packet with IP + UDP headers
    struct {
        struct iphdr ip;
        struct udphdr udp;
        uint8_t data[32];
    } __attribute__((packed)) packet;

    uint16_t pid = getpid() & 0xFFFF;
    uint16_t udp_len = sizeof(struct udphdr) + 32;
    uint16_t total_len = sizeof(struct iphdr) + udp_len;

    // Construct IP header with our PID as ID
    memset(&packet, 0, sizeof(packet));
    packet.ip.version = 4;
    packet.ip.ihl = 5;
    packet.ip.tos = 0;
    packet.ip.tot_len = htons(total_len);
    packet.ip.id = htons(pid);  // Use PID as IP ID for identification
    packet.ip.frag_off = 0;
    packet.ip.ttl = ttl;
    packet.ip.protocol = IPPROTO_UDP;
    packet.ip.check = 0;
    packet.ip.saddr = INADDR_ANY;
    packet.ip.daddr = ctx.dest_sockaddr->sin_addr.s_addr;
//    printf("packet.ip.id = %d (0x%04x)\n", ntohs(packet.ip.id), ntohs(packet.ip.id));

    // Construct UDP header
    packet.udp.source = htons(BASE_PORT + getpid());
    packet.udp.dest = htons(dest_port);
    packet.udp.len = htons(udp_len);
    packet.udp.check = 0; // UDP checksum optional for IPv4

    // Fill data with standard pattern
    for (int i = 0; i < 32; i++)
        packet.data[i] = 0x40 + (i % 64);

    // Calculate IP checksum (copy to avoid packed struct alignment issues)
    struct iphdr ip_copy = packet.ip;
    packet.ip.check = checksum((uint16_t*)&ip_copy, sizeof(ip_copy));

    // Send via raw socket
    debug_log("Sending raw packet with IP ID %d (0x%04x), TTL %d, dest port %d", pid, pid, ttl, dest_port);
    debug_log("Packet IP header: version=%d, ihl=%d, id=%d (0x%04x)", packet.ip.version, packet.ip.ihl, ntohs(packet.ip.id), ntohs(packet.ip.id));
    ssize_t bytes_sent = sendto(ctx.udp_socket, &packet, total_len, 0,
                               SOCKADDR(ctx.dest_sockaddr), sizeof(*ctx.dest_sockaddr));

    if (bytes_sent < 0) {
        print_failed("sendto() raw", errno);
        return (-1);
    }

    debug_log("Sent %zd bytes via raw socket", bytes_sent);
    return (0);
}


#define RECV_ICMP_ERROR -1
#define RECV_ICMP_TIMEOUT 0
#define RECV_ICMP_TTL_EXCEEDED 1
#define RECV_ICMP_DEST_REACHED 2
#define RECV_ICMP_IGNORED 3
int receive_icmp_response(uint8_t expected_hop, struct timeval *send_time, int probe_port)
{
    fd_set read_fds;
    struct timeval timeout;
    icmp_response_packet_t response;

    // Set timeout for response
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = TIMEOUT_USEC;

    FD_ZERO(&read_fds);
    FD_SET(ctx.icmp_socket, &read_fds);

    debug_log("Calling select() for hop %d port %d", expected_hop, probe_port);
    int select_result = select(ctx.icmp_socket + 1, &read_fds, NULL, NULL, &timeout);
    debug_log("select() returned: %d", select_result);

    if (select_result < 0)
    {
        print_failed("select()", errno);
        return (RECV_ICMP_ERROR);
    }
    
    if (select_result == 0) {
        debug_log("TIMEOUT: No ICMP packets received for hop %d port %d", expected_hop, probe_port);
        return (RECV_ICMP_TIMEOUT);
    }
    
    // Receive ICMP response
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    debug_log("About to receive ICMP packet...");
    ssize_t bytes_received = recvfrom(ctx.icmp_socket, &response, sizeof(response), 0,
                                     SOCKADDR(&from_addr), &from_len);

    if (bytes_received < 0)
    {
        print_failed("recvfrom()", errno);
        return (RECV_ICMP_ERROR);
    }

    // Get receive time
    struct timeval recv_time;
    gettimeofday(&recv_time, NULL);
    debug_log("Received %zd bytes from %s, ICMP type=%d code=%d", bytes_received, inet_ntoa(from_addr.sin_addr), response.icmp.type, response.icmp.code);

    // Validate ICMP response
    debug_log("Validating ICMP packet: type=%d code=%d for port %d", response.icmp.type, response.icmp.code, probe_port);
    int packet_status = validate_icmp_response(&response, getpid(), expected_hop);
    debug_log("Validation result: %d", packet_status);
    if (packet_status == VALIDATE_ICMP_ERROR) {
      debug_log("ICMP validation error - rejecting packet");
        return (RECV_ICMP_ERROR); // TODO: fix RECV_ICMP_TIMEOUT
    }
    else if (packet_status == VALIDATE_ICMP_IGNORED) {
      debug_log("ICMP packet ignored - not our packet");
        return (RECV_ICMP_IGNORED);
    }

    // Calculate RTT
    time_t rtt = get_difference_timeval(*send_time, recv_time);

    // Get source IP (the router that responded)
    string_hostname_t source_ip = resolve_address_from_int(AF_INET, from_addr.sin_addr.s_addr, 0);

    // Add hop result
    ctx_add_hop_result(expected_hop, source_ip, rtt, ctx.stats.hops[expected_hop - 1].received_probes);

    // Check if destination reached
    if (is_destination_reached(&response))
    {
        ctx.stats.hops[expected_hop - 1].is_destination = 1;
        free(source_ip);
        return (RECV_ICMP_DEST_REACHED); // Destination reached
    }

    // Check if TTL exceeded (normal intermediate hop)
    if (is_ttl_exceeded(&response))
    {
        free(source_ip);
        return (RECV_ICMP_TTL_EXCEEDED); // TTL exceeded (normal response)
    }

    free(source_ip);
    return (RECV_ICMP_IGNORED); // Other ICMP message
}

// State machine approach: send one packet, receive one response
#define PROBE_ERROR 0
#define PROBE_TTL_EXCEEDED 1
#define PROBE_DEST_REACHED 2
#define PROBE_TIMEOUT 3
int traceroute_single_probe(uint8_t hop_number, uint8_t probe_number, uint16_t probe_port)
{
    struct timeval send_time;

    debug_log("--- Probe %d/%d for hop %d ---", probe_number + 1, PROBES_PER_HOP, hop_number);

    // Get send time
    gettimeofday(&send_time, NULL);
    debug_log("Send time: %ld.%06ld", send_time.tv_sec, send_time.tv_usec);

    // Send probe packet
    if (send_probe_packet(hop_number, probe_port) != 0)
    {
        debug_log("Failed to send probe packet");
        ctx_add_hop_result(hop_number, NULL, -1, probe_number);
        return PROBE_ERROR;
    }
    debug_log("Probe packet sent successfully");

    // Wait for response
    debug_log("Waiting for response to probe %d...", probe_number + 1);
    int response_result = RECV_ICMP_IGNORED;
    while (response_result == RECV_ICMP_IGNORED)
      response_result = receive_icmp_response(hop_number + probe_number, &send_time, probe_port);
    debug_log("Response result: %d", response_result);

    if (response_result == RECV_ICMP_TIMEOUT)
    {
        // Timeout
        debug_log("Probe %d timed out", probe_number + 1);
        ctx_add_hop_result(hop_number, NULL, -1, probe_number);
        return PROBE_TIMEOUT;
    }
    else if (response_result == RECV_ICMP_TTL_EXCEEDED)
        return (PROBE_TTL_EXCEEDED);
    else if (response_result == RECV_ICMP_DEST_REACHED)
        return (PROBE_DEST_REACHED);

    // Error
    debug_log("Error receiving response for probe %d", probe_number + 1);
    ctx_add_hop_result(hop_number, NULL, -1, probe_number);
    return PROBE_ERROR;
}

int print_hop_info(hop_result_t *hop, int probe, int print_host)
{
    int resolved = 0;

    if (hop->ip_addr)
    {
        if (print_host) {
            if (hop->hostname && strcmp(hop->hostname, hop->ip_addr) != 0)
            {
                printf(" %s (%s)", hop->hostname, hop->ip_addr);
            }
            else
            {
                printf(" %s (%s)", hop->ip_addr, hop->ip_addr);
            }
            resolved = 1;
        }

        // Print timing measurements
        if (hop->rtt[probe] >= 0)
        {
            printf("  %.3f ms", (float)hop->rtt[probe] / 1000.0f);
        }
    }
    return (resolved);
}

int resolve_hop_host(hop_result_t *hop)
{
    if (hop->ip_addr)
    {
        // Resolve hostname for this IP if not already done
        if (hop->hostname == NULL)
        {
            struct sockaddr_in addr;
            inet_pton(AF_INET, hop->ip_addr, &addr.sin_addr);
            hop->hostname = resolve_hostname_from_ip(addr.sin_addr.s_addr, 0);
        }
        return 1;
    }
    return 0;
}

// Flush ICMP socket buffer
void flush_icmp_socket() {
    fd_set read_fds;
    struct timeval timeout = {0, 0}; // Non-blocking
    icmp_response_packet_t dummy;

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(ctx.icmp_socket, &read_fds);

        int result = select(ctx.icmp_socket + 1, &read_fds, NULL, NULL, &timeout);
        if (result <= 0) break; // No more packets

        // Read and discard packet
        recvfrom(ctx.icmp_socket, &dummy, sizeof(dummy), 0, NULL, NULL);
        debug_log("Flushed old ICMP packet from buffer");
    }
}

int traceroute_hop(uint8_t hop_number)
{
    int destination_reached = 0;

    debug_log("=== Starting hop %d ===", hop_number);

    // Flush old ICMP packets from buffer
    flush_icmp_socket();

    printf("%2d  ", hop_number);

    // Track which probe IPs have been resolved to avoid duplicate hostnames
    string_hostname_t resolved_ips[PROBES_PER_HOP] = {NULL};
    int resolved_count = 0;

    // Send probes one by one using state machine approach
    for (int probe = 0; probe < PROBES_PER_HOP; probe++)
    {
        uint16_t probe_port = ctx.current_port + probe;
        int result = traceroute_single_probe(hop_number, probe, probe_port);
        if (result == PROBE_DEST_REACHED)
        {
            destination_reached = 1;
            // Continue with remaining probes for this hop
        }
        if (result == PROBE_TIMEOUT) {
          printf(" *");
          fflush(stdout);
          continue;
        }

        hop_result_t *hop = &ctx.stats.hops[hop_number - 1];

        // Check if this IP has already been resolved
        uint8_t print_host = 0;
        string_hostname_t current_ip = hop->ip_addr;
        uint8_t already_seen = 0;

        if (current_ip) {
            for (int i = 0; i < resolved_count; i++) {
                if (resolved_ips[i] && strcmp(resolved_ips[i], current_ip) == 0) {
                    already_seen = 1;
                    break;
                }
            }
        }

        if (!already_seen) {
            print_host = resolve_hop_host(hop);
            resolve_hop_host(hop);
            if (print_host && resolved_count < PROBES_PER_HOP && current_ip) {
                resolved_ips[resolved_count] = strdup(current_ip);
                resolved_count++;
            }
        }

        print_hop_info(hop, probe, print_host);
        fflush(stdout);
    }

    // Cleanup allocated IP strings
    for (int i = 0; i < resolved_count; i++) {
        if (resolved_ips[i]) {
            free(resolved_ips[i]);
        }
    }

    printf("\n");
    return destination_reached;
}

int traceroute(string_hostname_t host, int options)
{
    // Initialize context
    int init_err = init_ctx(host, options);
    if (init_err != 0)
        return (init_err);
    
    printf("traceroute to %s (%s), %d hops max, 60 byte packets\n",
           ctx.stats.dest_hostname, ctx.stats.dest_addr, ctx.stats.max_hops);
    
    // Main TTL progression loop
    for (uint8_t hop = 1; hop <= ctx.stats.max_hops; hop++)
    {
        ctx.current_ttl = hop;

        int destination_reached = traceroute_hop(hop);

        ctx.current_port += PROBES_PER_HOP;
        
        if (destination_reached)
        {
            ctx.stats.total_hops = hop;
            break;
        }
    }
    
    return (0);
}

int main(int ac, char **av)
{
    if (getuid() != 0)
    {
        fprintf(stderr, "ft_traceroute: this program must be run as root\n");
        return (1);
    }
    
    if (ac < 2)
    {
        fprintf(stderr, "Usage: %s [--help] <destination>\n", av[0]);
        return (1);
    }
    
    int options = get_options(ac, av);
    if (options < 0)
        return (1);
    
    if (options & OPT_HELP)
        return (print_usage(av[0]));
    
    // Set up signal handlers
    signal(SIGINT, on_interrupt);
    
    int host_idx = get_host_arg(ac, av);
    if (host_idx < 0)
    {
        fprintf(stderr, "%s: missing host operand\n", av[0]);
        fprintf(stderr, "Try '%s --help' for more information\n", av[0]);
        return (1);
    }
    
    int result = traceroute(av[host_idx], options);
    destroy_ctx();
    return (result);
}
