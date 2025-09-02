#include "time_utils.h"

time_t  timeval_to_time(const struct timeval time)
{
    return (time.tv_sec * 1000000 + time.tv_usec);
}

time_t  get_difference_time(const time_t t1, const time_t t2)
{
    time_t diff_time;

    diff_time = t2 - t1;
    return (diff_time); // could overflow if difference time too large
}

time_t  get_difference_timeval(const struct timeval tv1, const struct timeval tv2)
{
    struct timeval diff_time;

    diff_time.tv_sec = tv2.tv_sec - tv1.tv_sec;
    diff_time.tv_usec = tv2.tv_usec - tv1.tv_usec;
    
    if (tv1.tv_usec > tv2.tv_usec)
    {
        diff_time.tv_sec--;
        diff_time.tv_usec = tv2.tv_usec + 1000000 - tv1.tv_usec;
    }
    else
    {
        diff_time.tv_usec = tv2.tv_usec - tv1.tv_usec;
    }
    return (diff_time.tv_sec * 1000000 + diff_time.tv_usec); // could overflow if difference time too large
}
