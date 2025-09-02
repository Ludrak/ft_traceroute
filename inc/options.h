#ifndef OPTIONS_H
#define OPTIONS_H

#include <stdio.h>

#define OPT_HELP    0b0001
#define OPT_VERBOSE 0b0010

int get_options(int ac, char **av);
int print_usage(char *pname);
int get_host_arg(int ac, char **av);

#endif
