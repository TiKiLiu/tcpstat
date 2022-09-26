#ifndef __TCPSTAT_UTIL_H
#define __TCPSTAT_UTIL_H

#include <sys/resource.h>
#include <arpa/inet.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>

#define warn(...) fprintf(stderr, __VA_ARGS__)

// static int get_int(const char *arg, int *ret, int min, int max)
// {
// 	char *end;
// 	long val;

// 	errno = 0;
// 	val = strtol(arg, &end, 10);
// 	if (errno) {
// 		warn("strtol: %s: %s\n", arg, strerror(errno));
// 		return -1;
// 	} else if (end == arg || val < min || val > max) {
// 		return -1;
// 	}
// 	if (ret)
// 		*ret = val;
// 	return 0;
// }

static int get_ints(const char *arg, int *size, int *ret, int min, int max)
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

// static int get_uint(const char *arg, unsigned int *ret,
// 		    unsigned int min, unsigned int max)
// {
// 	char *end;
// 	long val;

// 	errno = 0;
// 	val = strtoul(arg, &end, 10);
// 	if (errno) {
// 		warn("strtoul: %s: %s\n", arg, strerror(errno));
// 		return -1;
// 	} else if (end == arg || val < min || val > max) {
// 		return -1;
// 	}
// 	if (ret)
// 		*ret = val;
// 	return 0;
// }

#endif