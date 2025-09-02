#include "traceroute.h"
#include <linux/filter.h>

extern traceroute_ctx_t ctx;

static int set_socket_options(int socket, int options)
{
    // setting recv buffer size 
    int recv_buffer_size = 0x400;
    if (setsockopt(socket, SOL_SOCKET, SO_RCVBUF, &recv_buffer_size, sizeof(recv_buffer_size)) != 0)
    {
        if (options & OPT_VERBOSE)
            print_failed("setsockopt(SO_RCVBUF)", errno);
        return (errno);
    }

    // setting option to include iphdr when receiving
    int header_incl = 1;
    if (setsockopt(socket, IPPROTO_IP, IP_HDRINCL, &header_incl, sizeof(header_incl)) != 0)
    {
        if (options & OPT_VERBOSE)
            print_failed("setsockopt(IP_HDRINCL)", errno);
        return (errno);
    }

    // setting reuse port, so that packets will be sent to any process listening even on the same address/port
    int reuse_port = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, &reuse_port, sizeof(reuse_port)) != 0)
    {
        if (options & OPT_VERBOSE)
            print_failed("setsockopt(SO_REUSEPORT)", errno);
        return (errno);
    }

    return (0);
}

int init_ctx(const string_hostname_t hostname, int options)
{
    bzero(&ctx, sizeof(ctx));

    // creating UDP socket for sending probes
    ctx.udp_socket = create_udp_socket(options);
    if (ctx.udp_socket <= 0)
    {
        return (errno);
    }

    // Bind to a specific source port for identification
    struct sockaddr_in src_addr;
    bzero(&src_addr, sizeof(src_addr));
    src_addr.sin_family = AF_INET;
    src_addr.sin_addr.s_addr = INADDR_ANY;

    // Use a more unique port calculation: PID + current time microseconds
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint16_t unique_port = 32768 + ((getpid() ^ tv.tv_usec) & 0x7FFF);
    src_addr.sin_port = htons(unique_port);

    if (bind(ctx.udp_socket, SOCKADDR(&src_addr), sizeof(src_addr)) != 0)
    {
        if (options & OPT_VERBOSE)
            print_failed("bind(UDP)", errno);
        // Try with a random port if bind fails
        src_addr.sin_port = 0; // Let kernel choose
        if (bind(ctx.udp_socket, SOCKADDR(&src_addr), sizeof(src_addr)) != 0)
        {
            if (options & OPT_VERBOSE)
                print_failed("bind(UDP) with auto port", errno);
        }
    }

    // Store the actual bound port for validation
    socklen_t addr_len = sizeof(src_addr);
    if (getsockname(ctx.udp_socket, SOCKADDR(&src_addr), &addr_len) == 0)
    {
        ctx.source_port = ntohs(src_addr.sin_port);
        if (options & OPT_VERBOSE)
            printf("Bound to source port: %d\n", ctx.source_port);
    }

    // creating ICMP socket for receiving responses
    ctx.icmp_socket = create_icmp_socket(options);
    if (ctx.icmp_socket <= 0)
    {
        close(ctx.udp_socket);
        return (errno);
    }

    // setting options to the ICMP socket
    int err = set_socket_options(ctx.icmp_socket, options);
    if (err != 0)
    {
        close(ctx.udp_socket);
        close(ctx.icmp_socket);
        return err; 
    }

    // resolving address from hostname
    ctx.dest_sockaddr = resolve_address(hostname, options);
    if (ctx.dest_sockaddr == NULL)
    {
        printf ("ft_traceroute: cannot resolve address\n");
        close(ctx.udp_socket);
        close(ctx.icmp_socket);
        return (1);
    }

    // resolving hostname
    ctx.stats.dest_addr = resolve_hostname(*ctx.dest_sockaddr, options);
    if (!ctx.stats.dest_addr)
    {
        printf ("ft_traceroute: unknown host\n");
        close(ctx.udp_socket);
        close(ctx.icmp_socket);
        free(ctx.dest_sockaddr);
        return (1);
    }

    // Initialize traceroute statistics
    ctx.stats.dest_hostname = strdup(hostname);
    ctx.stats.total_hops = 0;
    ctx.stats.max_hops = MAX_HOPS;
    ctx.stats.current_hop = 1;
    ctx.current_port = DEFAULT_PORT;
    ctx.current_ttl = 1;

    // Initialize hop results
    for (int i = 0; i < MAX_HOPS; i++)
    {
        ctx.stats.hops[i].hop_number = i + 1;
        ctx.stats.hops[i].ip_addr = NULL;
        ctx.stats.hops[i].hostname = NULL;
        ctx.stats.hops[i].received_probes = 0;
        ctx.stats.hops[i].timeout_probes = 0;
        ctx.stats.hops[i].is_destination = 0;
        for (int j = 0; j < PROBES_PER_HOP; j++)
        {
            ctx.stats.hops[i].rtt[j] = -1;
        }
    }

    return (0);
}

int ctx_add_hop_result(const uint8_t hop, const string_hostname_t ip, const time_t rtt, const uint8_t probe_num)
{
    if (hop == 0 || hop > MAX_HOPS || probe_num >= PROBES_PER_HOP)
        return (1);

    hop_result_t *hop_result = &ctx.stats.hops[hop - 1];
    
    // Set IP address if not already set
    if (hop_result->ip_addr == NULL && ip != NULL)
    {
        hop_result->ip_addr = strdup(ip);
    }
    
    // Add RTT measurement
    if (probe_num < PROBES_PER_HOP)
    {
        hop_result->rtt[probe_num] = rtt;
        if (rtt >= 0)
            hop_result->received_probes++;
        else
            hop_result->timeout_probes++;
    }

    return (0);
}

void destroy_ctx()
{
    if (ctx.udp_socket > 0)
        close(ctx.udp_socket);
    if (ctx.icmp_socket > 0)
        close(ctx.icmp_socket);
    
    if (ctx.dest_sockaddr)
        free(ctx.dest_sockaddr);
    if (ctx.stats.dest_addr)
        free(ctx.stats.dest_addr);
    if (ctx.stats.dest_hostname)
        free(ctx.stats.dest_hostname);

    // Free hop result data
    for (int i = 0; i < MAX_HOPS; i++)
    {
        if (ctx.stats.hops[i].ip_addr)
            free(ctx.stats.hops[i].ip_addr);
        if (ctx.stats.hops[i].hostname)
            free(ctx.stats.hops[i].hostname);
    }
}
