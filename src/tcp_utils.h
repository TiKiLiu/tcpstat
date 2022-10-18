#ifndef _TCP_UTILS_H_
#define _TCP_UTILS_H_

#include <sys/resource.h>
#include <arpa/inet.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>

#define warn(...) fprintf(stderr, __VA_ARGS__)

int get_int(const char *arg, uint32_t *ret, int min, int max)
{
	char *end;
	long val;

	errno = 0;
	val = strtol(arg, &end, 10);
	if (errno) {
		warn("strtol: %s: %s\n", arg, strerror(errno));
		return -1;
	} else if (end == arg || val < min || val > max) {
		return -1;
	}
	if (ret)
		*ret = val;
	return 0;
}

int get_ints(const char *arg, int *size, uint32_t *ret, int min, int max)
{
	const char *argp = arg;
	int max_size = *size;
	int sz = 0;
	char *end;
	long val;

	while (sz < max_size) {
		errno = 0;
		val = strtol(argp, &end, 10);
		if (errno) {
			warn("strtol: %s: %s\n", arg, strerror(errno));
			return -1;
		} else if (end == arg || val < min || val > max) {
			return -1;
		}
		ret[sz++] = val;
		if (*end == 0)
			break;
		argp = end + 1;
	}

	*size = sz;
	return 0;
}

time_t get_timestamp()
{
    time_t t;
    time(&t);
    return t;
}

#endif