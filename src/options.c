#include "options.h"
#include "traceroute.h"

int get_options(int ac, char **av)
{
    int options = 0;
    
    for (int i = 1; i < ac; i++)
    {
        if (strcmp(av[i], "--help") == 0)
        {
            options |= OPT_HELP;
        }
        else if (strcmp(av[i], "-v") == 0 || strcmp(av[i], "--verbose") == 0)
        {
            options |= OPT_VERBOSE;
        }
        else if (av[i][0] == '-')
        {
            fprintf(stderr, "ft_traceroute: invalid option -- '%s'\n", av[i]);
            fprintf(stderr, "Try 'ft_traceroute --help' for more information.\n");
            return (-1);
        }
    }
    
    return (options);
}

int print_usage(char *pname)
{
    printf("Usage: %s [OPTION]... HOST\n", pname);
    printf("Print the route packets trace to network host.\n\n");
    printf("  --help     display this help and exit\n");
    printf("  -v, --verbose  verbose output\n\n");
    printf("Examples:\n");
    printf("  %s google.com        # trace route to google.com\n", pname);
    printf("  %s 8.8.8.8           # trace route to 8.8.8.8\n", pname);
    printf("  %s --verbose google.com  # trace with verbose output\n\n", pname);
    printf("This traceroute implementation sends UDP packets with incrementing TTL values\n");
    printf("and listens for ICMP Time Exceeded messages from intermediate routers.\n");
    printf("When the destination is reached, an ICMP Port Unreachable message is expected.\n\n");
    printf("Report bugs to: <your-email@example.com>\n");
    return (0);
}

int get_host_arg(int ac, char **av)
{
    // Find the first non-option argument (the hostname)
    for (int i = 1; i < ac; i++)
    {
        if (av[i][0] != '-')
        {
            return (i);
        }
    }
    return (-1);
}
