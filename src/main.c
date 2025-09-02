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

size_t construct_probe_packet(traceroute_packet_t *packet, uint8_t ttl, uint16_t dest_port)
{
    uint16_t udp_length = sizeof(struct udphdr) + sizeof(struct timeval) + 32;
    uint16_t total_length = sizeof(struct iphdr) + udp_length;
    
    struct iphdr ip_header = construct_traceroute_iphdr(*ctx.dest_sockaddr, ttl, total_length);
    struct udphdr udp_header = construct_traceroute_udphdr(0, dest_port, udp_length);
    
    size_t packet_size = construct_traceroute_packet(packet, ip_header, udp_header);
    write_packet_time(packet);
    
    // Fill data section with pattern
    memset(&packet->data, 0x40 + ttl, sizeof(packet->data));
    
    return packet_size;
}

int send_probe_packet(uint8_t ttl, uint16_t dest_port)
{
    debug_log("Sending probe: TTL=%d, dest_port=%d", ttl, dest_port);

    // Set TTL on UDP socket
    if (set_socket_ttl(ctx.udp_socket, ttl) != 0)
    {
        print_failed("set_socket_ttl()", errno);
        return (-1);
    }

    // Send UDP packet (only UDP payload, kernel adds IP header)
    struct sockaddr_in dest_addr = *ctx.dest_sockaddr;
    dest_addr.sin_port = htons(dest_port);

    // Create UDP payload with PID for identification
    uint8_t udp_payload[32];
    uint16_t pid = getpid() & 0xFFFF;

    // Put PID in first 2 bytes of payload
    udp_payload[0] = (pid >> 8) & 0xFF;
    udp_payload[1] = pid & 0xFF;

    // Fill rest with pattern
    for (int i = 2; i < 32; i++)
        udp_payload[i] = '*';

    debug_log("About to sendto() with %zu bytes", sizeof(udp_payload));
    ssize_t bytes_sent = sendto(ctx.udp_socket, udp_payload,
                               sizeof(udp_payload), 0,
                               SOCKADDR(&dest_addr), sizeof(dest_addr));

    if (bytes_sent < 0)
    {
        print_failed("sendto()", errno);
        return (-1);
    }

    debug_log("Packet sent successfully: %zd bytes", bytes_sent);
    return (0);
}


#define RECV_ICMP_ERROR -1
#define RECV_ICMP_TIMEOUT 0
#define RECV_ICMP_TTL_EXCEEDED 1
#define RECV_ICMP_DEST_REACHED 2
#define RECV_ICMP_INVALID 3
int receive_icmp_response(uint8_t expected_hop, uint16_t expected_port, struct timeval *send_time)
{
    debug_log("Waiting for ICMP response: hop=%d, port=%d, timeout=%d.%06ds", expected_hop, expected_port, TIMEOUT_SEC, TIMEOUT_USEC);

    fd_set read_fds;
    struct timeval timeout;
    icmp_response_packet_t response;

    // Set timeout for response
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = TIMEOUT_USEC;

    FD_ZERO(&read_fds);
    FD_SET(ctx.icmp_socket, &read_fds);

    debug_log("Calling select() with timeout %d.%06ld", timeout.tv_sec, timeout.tv_usec);
    int select_result = select(ctx.icmp_socket + 1, &read_fds, NULL, NULL, &timeout);
    debug_log("select() returned: %d", select_result);

    if (select_result < 0)
    {
        print_failed("select()", errno);
        return (RECV_ICMP_ERROR);
    }
    
    if (select_result == 0)
    {
        // Timeout
        debug_log("TIMEOUT: No response received within %d.%06d seconds", TIMEOUT_SEC, TIMEOUT_USEC);
        return (RECV_ICMP_TIMEOUT);
    }
    
    // Receive ICMP response
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    debug_log("Receiving ICMP packet...");
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
    debug_log("Received %zd bytes from %s", bytes_received, inet_ntoa(from_addr.sin_addr));

    // Validate ICMP response
    debug_log("Validating ICMP response...");
    int packet_status = validate_icmp_response(&response, getpid() & 0xFFFF);
    if (packet_status == 0)
    {
        debug_log("ICMP packet validation failed - not our packet");
        return (0);
    }
    else if (packet_status == 2) {
        return (RECV_ICMP_INVALID);
    }
    debug_log("ICMP packet validation successful");
    
    // Calculate RTT
    time_t rtt = get_difference_timeval(*send_time, recv_time);

    // Get source IP (the router that responded)
    string_hostname_t source_ip = resolve_address_from_int(AF_INET, from_addr.sin_addr.s_addr, 0);

    // Add hop result
    ctx_add_hop_result(expected_hop, source_ip, rtt, ctx.stats.hops[expected_hop - 1].received_probes);

    // Get ICMP annotation for error codes
    const char* annotation = get_icmp_annotation(&response);
    if (strlen(annotation) > 0)
    {
        debug_log("ICMP annotation: %s", annotation);
        // TODO: Store annotation in hop result for display
    }

    // Check if destination reached
    if (is_destination_reached(&response))
    {
        ctx.stats.hops[expected_hop - 1].is_destination = 1;
        free(source_ip);
        return (2); // Destination reached
    }

    // Check if TTL exceeded (normal intermediate hop)
    if (is_ttl_exceeded(&response))
    {
        free(source_ip);
        return (RECV_ICMP_TTL_EXCEEDED); // TTL exceeded (normal response)
    }

    free(source_ip);
    return (RECV_ICMP_INVALID); // Other ICMP message
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
    int response_result = 3;
    while (response_result == 3) // debounce ignored packets
      response_result = receive_icmp_response(hop_number, probe_port, &send_time);
    debug_log("Response result: %d", response_result);

    if (response_result == 0)
    {
        // Timeout
        debug_log("Probe %d timed out", probe_number + 1);
        ctx_add_hop_result(hop_number, NULL, -1, probe_number);
        return PROBE_TIMEOUT;
    }
    else if (response_result == 1 || response_result == 2)
    {
        // Valid response - result already stored in ctx_add_hop_result
        debug_log("Valid response received for probe %d", probe_number + 1);
        if (response_result == 2)
        {
            debug_log("Destination reached!");
            return PROBE_DEST_REACHED; // Destination reached
        }
        return PROBE_TTL_EXCEEDED; // Normal response
    }
    else
    {
        // Error
        debug_log("Error receiving response for probe %d", probe_number + 1);
        ctx_add_hop_result(hop_number, NULL, -1, probe_number);
        return PROBE_ERROR;
    }
}

int traceroute_hop(uint8_t hop_number)
{
    int destination_reached = 0;

    debug_log("=== Starting hop %d ===", hop_number);
    printf("%2d  ", hop_number);

    uint8_t resolved = 0;

    // Send probes one by one using state machine approach
    for (int probe = 0; probe < PROBES_PER_HOP; probe++)
    {
        uint16_t probe_port = ctx.current_port + probe;
        int result = traceroute_single_probe(hop_number, probe, probe_port);
        if (result == 2)
        {
            destination_reached = 1;
            printf("reach");
            // Continue with remaining probes for this hop
        }
        if (result == 3) {
          printf(" *");
          fflush(stdout);
          continue;
        }

        // Print hop information
        hop_result_t *hop = &ctx.stats.hops[hop_number - 1];
        if (hop->ip_addr)
        {
            // Resolve hostname for this IP if not already done
            if (hop->hostname == NULL)
            {
                struct sockaddr_in addr;
                inet_pton(AF_INET, hop->ip_addr, &addr.sin_addr);
                hop->hostname = resolve_hostname_from_ip(addr.sin_addr.s_addr, 0);
            }

            if (!resolved) {
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
//            else
//            {
//                printf("  *");
//            }
//        } else {
//            printf("  *");
//        }
    }
    
//    // Print hop information
//    hop_result_t *hop = &ctx.stats.hops[hop_number - 1];
//    if (hop->ip_addr)
//    {
//        // Resolve hostname for this IP if not already done
//        if (hop->hostname == NULL)
//        {
//            struct sockaddr_in addr;
//            inet_pton(AF_INET, hop->ip_addr, &addr.sin_addr);
//            hop->hostname = resolve_hostname_from_ip(addr.sin_addr.s_addr, 0);
//        }
//
//        // Print in format: hostname (IP) or just IP if no hostname
//        if (hop->hostname && strcmp(hop->hostname, hop->ip_addr) != 0)
//        {
//            printf(" %s (%s)", hop->hostname, hop->ip_addr);
//        }
//        else
//        {
//            printf(" %s", hop->ip_addr);
//        }
//
//        // Print timing measurements
//        for (int i = 0; i < PROBES_PER_HOP; i++)
//        {
//            if (hop->rtt[i] >= 0)
//            {
//                printf("  %.3f ms", (float)hop->rtt[i] / 1000.0f);
//            }
//            else
//            {
//                printf("  *");
//            }
//        }
//    }
//    else
//    {
//        // No IP address received, print all timeouts
//        printf(" *  *  *");
//    }

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
        ctx.current_port = DEFAULT_PORT + (hop - 1) * PROBES_PER_HOP;
        
        int destination_reached = traceroute_hop(hop);
        
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
