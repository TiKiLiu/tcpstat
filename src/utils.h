#ifndef _UTILS_H_
#define _UTILS_H_

#include <time.h>

time_t get_timestamp()
{
    time_t t;
    time(&t);
    return t;
}

#endif