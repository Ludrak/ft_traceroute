#include "packet.h"
#include "time_utils.h"

size_t construct_traceroute_packet(traceroute_packet_t *const pk, const struct iphdr ip_header, const struct udphdr udp_header)
{
    bzero(pk, sizeof(*pk));
    memcpy(&pk->ip, (void *)&ip_header, sizeof(struct iphdr));
    memcpy(&pk->udp, (void *)&udp_header, sizeof(struct udphdr));
    return (sizeof(*pk));
}

ssize_t construct_packet_from_data(void *const pk, const void *const data, const size_t data_size)
{
    if (data_size > MAX_PACKET_SIZE)
    {
        printf("INVALID SIZE FOR CONSTRUCTING PACKET\n");
        return (MAX_PACKET_SIZE - data_size);
    }
    memcpy(pk, data, data_size);
    return (0);
}

size_t write_packet_time(traceroute_packet_t *const pk)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    memcpy(&pk->time, (void *)&tv, sizeof(struct timeval));
    return (sizeof(*pk));
}

struct iphdr construct_traceroute_iphdr(const struct sockaddr_in dest_address, uint8_t ttl, uint16_t total_length)
{
    struct iphdr header = (struct iphdr){
        .version = 4,
        .ihl = sizeof(struct iphdr) / 4,
        .tos = 0,
        .tot_len = htons(total_length),
        .id = htons(getpid() & 0xFFFF),
        // [0]RESERVED [1]MF [2]DF [.*13]fragments count
        .frag_off = 0,
        .ttl = ttl,
        .protocol = IPPROTO_UDP,
        .check = 0,
        .saddr = INADDR_ANY,
        .daddr = dest_address.sin_addr.s_addr
    };
    header.check = checksum((uint16_t *)&header, sizeof(header));
    return (header);
}

struct udphdr construct_traceroute_udphdr(uint16_t src_port, uint16_t dest_port, uint16_t length)
{
    struct udphdr header = (struct udphdr){
        .source = htons(src_port),
        .dest = htons(dest_port),
        .len = htons(length),
        .check = 0  // UDP checksum is optional for IPv4
    };
    return (header);
}

int parse_icmp_response(icmp_response_packet_t pk, char *err_buffer)
{
    switch (pk.icmp.type)
    {
        case ICMP_TIME_EXCEEDED:
            if (pk.icmp.code == ICMP_EXC_TTL)
            {
                strcpy(err_buffer, "Time to live exceeded");
                return (11); // ICMP Type 11
            }
            break;
            
        case ICMP_DEST_UNREACH:
            switch (pk.icmp.code)
            {
                case ICMP_NET_UNREACH:
                    strcpy(err_buffer, "Destination Net Unreachable");
                    return (3);
                case ICMP_HOST_UNREACH:
                    strcpy(err_buffer, "Destination Host Unreachable");
                    return (3);
                case ICMP_PROT_UNREACH:
                    strcpy(err_buffer, "Destination Protocol Unreachable");
                    return (3);
                case ICMP_PORT_UNREACH:
                    strcpy(err_buffer, "Destination Port Unreachable");
                    return (3);
                case ICMP_FRAG_NEEDED:
                    strcpy(err_buffer, "Fragmentation needed and DF set");
                    return (3);
                case ICMP_SR_FAILED:
                    strcpy(err_buffer, "Source Route Failed");
                    return (3);
                case ICMP_NET_UNKNOWN:
                    strcpy(err_buffer, "Destination Net Unknown");
                    return (3);
                case ICMP_HOST_UNKNOWN:
                    strcpy(err_buffer, "Destination Host Unknown");
                    return (3);
                case ICMP_HOST_ISOLATED:
                    strcpy(err_buffer, "Source Host Isolated");
                    return (3);
                case ICMP_NET_ANO:
                    strcpy(err_buffer, "Communication with Destination Net Administratively Prohibited");
                    return (3);
                case ICMP_HOST_ANO:
                    strcpy(err_buffer, "Communication with Destination Host Administratively Prohibited");
                    return (3);
                case ICMP_NET_UNR_TOS:
                    strcpy(err_buffer, "Destination Net Unreachable for Type of Service");
                    return (3);
                case ICMP_HOST_UNR_TOS:
                    strcpy(err_buffer, "Destination Host Unreachable for Type of Service");
                    return (3);
                case ICMP_PKT_FILTERED:
                    strcpy(err_buffer, "Packet filtered");
                    return (3);
                case ICMP_PREC_VIOLATION:
                    strcpy(err_buffer, "Precedence violation");
                    return (3);
                case ICMP_PREC_CUTOFF:
                    strcpy(err_buffer, "Precedence cut off");
                    return (3);
                default:
                    strcpy(err_buffer, "Destination Unreachable");
                    return (3);
            }
            break;
            
        default:
            strcpy(err_buffer, "Unknown ICMP message");
            return (-1);
    }
    
    strcpy(err_buffer, "No error");
    return (0);
}
