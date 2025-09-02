#ifndef TIME_UTILS_H
#define TIME_UTILS_H

#include <sys/time.h>
#include <stdint.h>

typedef struct  s_time_list
{
    time_t  time;
    struct s_time_list *next;
}               time_list_t;

time_t  timeval_to_time(const struct timeval time);

time_t  get_difference_time(const time_t t1, const time_t t2);
time_t  get_difference_timeval(const struct timeval tv1, const struct timeval tv2);

#endif
