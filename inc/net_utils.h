#ifndef NET_TYPES_H
#define NET_TYPES_H

#include <stdlib.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <arpa/inet.h>

/* this is automatically defined when building, defining it for vscode to access completely netdb.h before build */
#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#include <netdb.h>

#include "print_utils.h"

#define MAX_HOSTNAME_SIZE_4 32

#define SOCKADDR(sock_addr_in)      ((struct sockaddr *)sock_addr_in)
#define SOCKADDR_IN(sock_addr)      ((struct sockaddr_in *)sock_addr)
#define COPY_SOCKADDR(dst, src) { (dst)->sa_family = (src)->sa_family; memcpy((dst)->sa_data, (src)->sa_data, 14 /* 14 bytes is not enough for IP6 addresses use sockaddr_storage for that */); }

/** NET TYPES */
typedef int32_t     socket_t;
typedef char*       string_hostname_t;

/* respectivly returns allocated struct sockaddr_in and char * containing the address or hostname requested  */
/* the given result MUST be freed after utilisation                                                          */
struct sockaddr_in  *resolve_address(const string_hostname_t hostname, int options);
string_hostname_t   resolve_hostname(const struct sockaddr_in address, int options);

string_hostname_t   resolve_address_from_int(const sa_family_t address_family, const uint32_t address, int options);
string_hostname_t   resolve_hostname_from_ip(const uint32_t ip_addr, int options);

// Additional functions for traceroute
int set_socket_ttl(socket_t socket, uint8_t ttl);
int create_udp_socket(int options);
int create_icmp_socket(int options);

#endif
