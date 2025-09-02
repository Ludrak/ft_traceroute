#include "print_utils.h"

#define MAX_MSG_CONTROL_SZ 2048
#define MAX_MSG_IOV_SZ     2048
#define MAX_MSG_NAME_SZ    1024

void    print_struct_msghdr(const struct msghdr header)
{
    char   msg_control[MAX_MSG_CONTROL_SZ];
    bzero(msg_control, MAX_MSG_CONTROL_SZ);
    strcpy(msg_control, "null");

    char   msg_iov[MAX_MSG_IOV_SZ];
    size_t msg_iovlen = 0;
    bzero(msg_iov, MAX_MSG_IOV_SZ);
    strcpy(msg_iov, "null");

    char   msg_name[MAX_MSG_NAME_SZ];
    bzero(msg_name, MAX_MSG_NAME_SZ);
    strcpy(msg_name, "null");

    // check for msg_control
    if (header.msg_controllen > 0 && header.msg_control)
    {
        strncpy(msg_control, header.msg_control, header.msg_controllen);
    }

    // check for msg_name
    if (header.msg_iovlen > 0 && header.msg_iov && header.msg_iov->iov_len > 0 && header.msg_iov->iov_base)
    {
        msg_iovlen = header.msg_iov->iov_len;
        strncpy(msg_name, header.msg_iov->iov_base, header.msg_iov->iov_len);
    }

    // check for msg_name
    if (header.msg_namelen > 0 && header.msg_name)
    {
        strncpy(msg_name, header.msg_name, header.msg_namelen);
    }

    printf("struct msghdr\n{\n    msg_control = \"%s\";\n    msg_controllen = %zu;\n    msg_flags = %d;\n    msg_iov->iov_base = \"%s\";\n    msg_iov->iovlen = %zu;\n    msg_iovlen = %zu;\n    msg_name = \"%s\";\n    msg_namelen = %d;\n}\n",
    msg_control, header.msg_controllen, header.msg_flags, msg_iov, msg_iovlen, header.msg_iovlen, msg_name, header.msg_namelen);
}

void    print_struct_iphdr(const struct iphdr header)
{
    printf("struct iphdr\n{\n    ihl = %hhu;\n    version = %hhu;\n    tos = %hhu;\n    tot_len = %hu;\n    id = %hu;\n    frag_off = %hu;\n    ttl = %hhu;\n    protocol = %hhu;\n    check = %hu;\n    saddr = 0x%.8x;\n    daddr = 0x%.8x;\n}\n",
    header.ihl, header.version, header.tos, header.tot_len, header.id, header.frag_off, header.ttl, header.protocol, header.check, header.saddr, header.daddr);
}

void    print_struct_icmphdr(const struct icmphdr header)
{
    printf ("struct icmphdr\n{\n    type = %hhu;\n    code = %hhu;\n    checksum = %hu;\n    un.echo.id = %hu;\n    un.echo.sequence = %hu;\n    un.gateway = %u;\n    un.frag.mtu = %hu;\n}\n",
    header.type, header.code, header.checksum, header.un.echo.id, header.un.echo.sequence, header.un.gateway, header.un.frag.mtu);
}

void    print_struct_udphdr(const struct udphdr header)
{
    printf ("struct udphdr\n{\n    source = %hu;\n    dest = %hu;\n    len = %hu;\n    check = %hu;\n}\n",
    header.source, header.dest, header.len, header.check);
}

void    print_struct_sockaddr_in(const struct sockaddr_in sockaddr)
{
    printf ("struct sockaddr_in\n{\n    sin_family = %hu;\n    sin_port = %hu;\n    sin_addr.s_addr = 0x%.8x;\n    sin_zero = '%s';\n}\n",
    sockaddr.sin_family, sockaddr.sin_port, sockaddr.sin_addr.s_addr, sockaddr.sin_zero);
}
