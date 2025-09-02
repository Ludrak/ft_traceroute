#ifndef PRINT_UTILS_H
#define PRINT_UTILS_H

#include <stdio.h>
#include <stddef.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <string.h>
#include <sys/time.h>

/** Print errno */
int     print_failed(const char *const caller, const int32_t err);

/** Print binary big endian and little endian */
void    print_binary_be(const void *const param, const size_t size);
void    print_binary_le(const void *const param, const size_t size);

/* Print time */
void    print_struct_timeval(const struct timeval t);

/** Print network */
void    print_struct_iphdr(const struct iphdr header);
void    print_struct_icmphdr(const struct icmphdr header);
void    print_struct_udphdr(const struct udphdr header);
void    print_struct_sockaddr_in(const struct sockaddr_in sockaddr);
void    print_struct_msghdr(const struct msghdr header);

#endif // PRINT_UTILS_H
