#include "packet.h"
#include "traceroute.h"

#include "print_utils.h"

// Validate that an ICMP response corresponds to our traceroute probe
int validate_icmp_response(icmp_response_packet_t *response, uint16_t expected_pid, uint16_t hop_count)
{
    if (getenv("TRACEROUTE_DEBUG")) {
        printf("[DEBUG] Validating ICMP: type=%d code=%d\n", response->icmp.type, response->icmp.code);
    }

    // Check if it's a relevant ICMP message type
    if (response->icmp.type != ICMP_TIME_EXCEEDED && response->icmp.type != ICMP_DEST_UNREACH) {
        if (getenv("TRACEROUTE_DEBUG")) {
            printf("[DEBUG] Invalid ICMP type: %d\n", response->icmp.type);
        }
        return (VALIDATE_ICMP_ERROR);
    }

    // For ICMP Time Exceeded and Destination Unreachable, the original packet
    // is included in the ICMP data. We need to extract and validate it.

    // The ICMP data contains the original IP header + 8 bytes of original data
    uint8_t *icmp_data = response->original_data;

    // Extract original IP header
    struct iphdr *orig_ip = (struct iphdr *)icmp_data;

    // Basic validation of original IP header
    if (orig_ip->version != 4 || orig_ip->protocol != IPPROTO_UDP)
        return (VALIDATE_ICMP_ERROR);

    // Extract original UDP header (after IP header)
    struct udphdr *orig_udp = (struct udphdr *)(icmp_data + (orig_ip->ihl * 4));

    (void)hop_count;
    int resolved_pid = ntohs(orig_udp->source) - BASE_PORT;

    if (resolved_pid != expected_pid) {
      return (VALIDATE_ICMP_IGNORED);
    }

    return (VALIDATE_ICMP_SUCCESS);
}

// Check if ICMP response indicates destination reached
int is_destination_reached(icmp_response_packet_t *response)
{
    return (response->icmp.type == ICMP_DEST_UNREACH &&
            response->icmp.code == ICMP_PORT_UNREACH);
}

// Check if ICMP response indicates TTL exceeded
int is_ttl_exceeded(icmp_response_packet_t *response)
{
    return (response->icmp.type == ICMP_TIME_EXCEEDED && 
            response->icmp.code == ICMP_EXC_TTL);
}

// Get the source IP address from ICMP response (the router that sent it)
uint32_t get_response_source_ip(icmp_response_packet_t *response)
{
    return response->ip.saddr;
}

// Validate basic packet structure
int validate_packet_structure(void *packet, size_t packet_size, int packet_type)
{
    if (packet == NULL || packet_size == 0)
        return (0);

    if (packet_type == IPPROTO_ICMP)
    {
        if (packet_size < sizeof(struct iphdr) + sizeof(struct icmphdr))
            return (0);
        
        struct iphdr *ip = (struct iphdr *)packet;
        if (ip->version != 4 || ip->protocol != IPPROTO_ICMP)
            return (0);
    }
    else if (packet_type == IPPROTO_UDP)
    {
        if (packet_size < sizeof(struct iphdr) + sizeof(struct udphdr))
            return (0);
        
        struct iphdr *ip = (struct iphdr *)packet;
        if (ip->version != 4 || ip->protocol != IPPROTO_UDP)
            return (0);
    }

    return (1);
}

// Handle network errors and convert to readable messages
int handle_network_error(int error_code, char *error_buffer, size_t buffer_size)
{
    switch (error_code)
    {
        case ENETUNREACH:
            snprintf(error_buffer, buffer_size, "Network is unreachable");
            break;
        case EHOSTUNREACH:
            snprintf(error_buffer, buffer_size, "Host is unreachable");
            break;
        case ECONNREFUSED:
            snprintf(error_buffer, buffer_size, "Connection refused");
            break;
        case ETIMEDOUT:
            snprintf(error_buffer, buffer_size, "Operation timed out");
            break;
        case EPERM:
            snprintf(error_buffer, buffer_size, "Operation not permitted (check root privileges)");
            break;
        case EACCES:
            snprintf(error_buffer, buffer_size, "Permission denied");
            break;
        case EINVAL:
            snprintf(error_buffer, buffer_size, "Invalid argument");
            break;
        case EMSGSIZE:
            snprintf(error_buffer, buffer_size, "Message too long");
            break;
        case ENOBUFS:
            snprintf(error_buffer, buffer_size, "No buffer space available");
            break;
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
            snprintf(error_buffer, buffer_size, "Resource temporarily unavailable");
            break;
        default:
            snprintf(error_buffer, buffer_size, "Unknown network error: %s", strerror(error_code));
            break;
    }
    return (error_code);
}

// REMOVED: validate_probe_packet() - validates unused packet structure

// Get traceroute annotation for ICMP error codes
const char* get_icmp_annotation(icmp_response_packet_t *pk)
{
    if (pk->icmp.type == ICMP_DEST_UNREACH)
    {
        switch (pk->icmp.code)
        {
            case ICMP_NET_UNREACH:
                return "!N";
            case ICMP_HOST_UNREACH:
                return "!H";
            case ICMP_PROT_UNREACH:
                return "!P";
            case ICMP_PORT_UNREACH:
                return ""; // Normal destination reached
            case ICMP_FRAG_NEEDED:
                return "!F";
            case ICMP_SR_FAILED:
                return "!S";
            case ICMP_NET_ANO:
            case ICMP_HOST_ANO:
                return "!X";
            case ICMP_PREC_VIOLATION:
                return "!V";
            case ICMP_PREC_CUTOFF:
                return "!C";
            default:
                return "!<num>";
        }
    }
    return "";
}
