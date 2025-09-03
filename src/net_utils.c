#include "net_utils.h"
#include "traceroute.h"

struct sockaddr_in  *resolve_address(const string_hostname_t host, int options)
{
    struct addrinfo *result = NULL;
    struct addrinfo hints = (struct addrinfo){
        .ai_flags = AI_CANONNAME,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };
    struct sockaddr  *address = NULL;

    int err = getaddrinfo(host, 0, &hints, &result);
    if (err != 0)
    {
        if (options & OPT_VERBOSE)
            fprintf(stderr, "getaddrinfo(): %s: %d: %s\n", host, err, gai_strerror(err));
        freeaddrinfo(result);
        return (NULL);
    }
    if (result != NULL)
    {
        address = malloc(sizeof(struct sockaddr_in));
        COPY_SOCKADDR(address, result->ai_addr);
        freeaddrinfo(result);
        return (SOCKADDR_IN(address));
    }
    freeaddrinfo(result);
    return (NULL);
}

string_hostname_t   resolve_hostname(const struct sockaddr_in address, int options)
{
    char host_buffer[MAX_HOSTNAME_SIZE_4];
    bzero(host_buffer, MAX_HOSTNAME_SIZE_4);
    if (inet_ntop(address.sin_family, &address.sin_addr.s_addr, host_buffer, MAX_HOSTNAME_SIZE_4) == NULL)
    {
        if (options & OPT_VERBOSE)
            print_failed("inet_ntop()", errno);
        return (NULL);
    }
    char *s_address = malloc(sizeof(char) * (strlen(host_buffer) + 1));
    if (!s_address)
    {
        return(NULL);
    }
    strcpy(s_address, host_buffer);
    return (s_address);
}

string_hostname_t   resolve_address_from_int(const sa_family_t address_family, const uint32_t address, int options)
{
    char host_buffer[MAX_HOSTNAME_SIZE_4];
    bzero(host_buffer, MAX_HOSTNAME_SIZE_4);
    if (inet_ntop(address_family, &address, host_buffer, MAX_HOSTNAME_SIZE_4) == NULL)
    {
        if (options & OPT_VERBOSE)
        print_failed("inet_ntop()", errno);
        return (NULL);
    }
    char *s_address = malloc(sizeof(char) * (strlen(host_buffer) + 1));
    if (!s_address)
    {
        return(NULL);
    }
    strcpy(s_address, host_buffer);
    return (s_address);
}

string_hostname_t resolve_hostname_from_ip(const uint32_t ip_addr, int options)
{
    struct sockaddr_in addr;
    char hostname[NI_MAXHOST];

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip_addr;

    int result = getnameinfo(SOCKADDR(&addr), sizeof(addr),
                           hostname, sizeof(hostname),
                           NULL, 0, NI_NAMEREQD);

    if (result != 0)
    {
        // If hostname resolution fails, return IP address
        return resolve_address_from_int(AF_INET, ip_addr, options);
    }

    char *resolved_hostname = malloc(strlen(hostname) + 1);
    if (!resolved_hostname)
        return resolve_address_from_int(AF_INET, ip_addr, options);

    strcpy(resolved_hostname, hostname);
    return resolved_hostname;
}

int set_socket_ttl(socket_t socket, uint8_t ttl)
{
    int ttl_val = (int)ttl;
    if (setsockopt(socket, IPPROTO_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0)
    {
        return (errno);
    }

    // Verify TTL was set correctly
    if (getenv("TRACEROUTE_DEBUG")) {
        int actual_ttl;
        socklen_t len = sizeof(actual_ttl);
        if (getsockopt(socket, IPPROTO_IP, IP_TTL, &actual_ttl, &len) == 0) {
            printf("[DEBUG] TTL verification: requested=%d, actual=%d\n", ttl, actual_ttl);
        }
    }

    return (0);
}

// checksum function already exists in checksum.c

int create_udp_socket(int options)
{
    // Create raw socket to control IP header (including IP ID)
    socket_t sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock <= 0)
    {
        if (options & OPT_VERBOSE)
            print_failed("socket(RAW)", errno);
        return (-1);
    }

    // Enable IP_HDRINCL to include our own IP header
    int hdrincl = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl)) < 0)
    {
        if (options & OPT_VERBOSE)
            print_failed("setsockopt(IP_HDRINCL)", errno);
        close(sock);
        return (-1);
    }

    // Enable broadcast (optional for traceroute)
    int broadcast = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) != 0)
    {
        if (options & OPT_VERBOSE)
            print_failed("setsockopt(SO_BROADCAST)", errno);
        close(sock);
        return (-1);
    }

    return (sock);
}

int create_icmp_socket(int options)
{
    socket_t sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock <= 0)
    {
        if (options & OPT_VERBOSE)
            print_failed("socket(ICMP)", errno);
        return (-1);
    }

    // Note: ICMP filter removed for debugging - all ICMP messages will be received

    return (sock);
}
