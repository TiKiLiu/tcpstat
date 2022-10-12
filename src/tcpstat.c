#include <sys/resource.h>
#include <arpa/inet.h>
#include <argp.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <bpf/bpf.h>
#include "tcpstat.h"
//#include "btf_helpers.h"
#include "tcpstat.skel.h"
#include "tcpstat_util.h"

static volatile sig_atomic_t exiting = 0;
static volatile sig_atomic_t timeout = 0;
static struct itimerval oldtv;

const char *argp_program_version = "tcpstat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char argp_program_doc[] =
	"\ntcpstat: Count/Trace active tcp connections\n"
	"\n"
	"EXAMPLES:\n"
	"    tcpstat             # trace all TCP connect()s\n"
	"    tcpstat -s 80       # only trace src port 80\n"
	"    tcpstat -s 80,81    # only trace src port 80 and 81\n"
	"    tcpstat -d 80       # only trace dst port 80\n"
	"    tcpstat -d 80,81    # only trace dst port 80 and 81\n"
	"    tcpstat -m 1        # open real-time sample\n"
	"    tcpstat -i 1000     # set sample interval 1000ms\n"
	"    tcpstat -t 1000     # the program runs for 1000 seconds\n"
	;

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "src port", 's', "PORTS", 0,
	  "Comma-separated list of destination ports to trace" },
	{ "dst port", 'd', "PORTS", 0,
	  "Comma-separated list of destination ports to trace" },
	{ "mode", 'm', "MODE", 0, "Sample mode, default 0, 1 means open real-time sample"},
	{ "interval", 'i', "INTERVAL", 0, "Real-time sample interval"},
	{ "file path", 'o', "FILE", 0, "Output into given file path"},
	{ "timeout", 't', "TIMEOUT", 0, "Timeout"},
	{ "IPv4 address", '4', "IPv4", 0, "Filter IPv4 address"},
	{ "IPv6 address", '6', "IPv6", 0, "Filter IPv6 address"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static FILE *fp;
static struct env {
	bool verbose;
	bool redirect;
	uint32_t uid;
	uint32_t nports[2];
	uint32_t ports[2][MAX_PORTS];
	uint32_t mode;
	uint32_t interval;
	uint32_t timeout;
	uint32_t raddr;
	unsigned __int128 raddr_v6;
	char fpath[256];
} env = {
	.uid = (uid_t) -1,
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int err;
	int nports;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 's':
		nports = MAX_PORTS;
		err = get_ints(arg, &nports, env.ports[0], 1, 65535);
		if (err) {
			warn("invalid PORT_LIST: %s\n", arg);
			argp_usage(state);
		}
		env.nports[0] = nports;
		break;
	case 'd':
		nports = MAX_PORTS;
		err = get_ints(arg, &nports, env.ports[1], 1, 65535);
		if (err) {
			warn("invalid PORT_LIST: %s\n", arg);
			argp_usage(state);
		}
		env.nports[1] = nports;
		break;
	case 'i':
		err = get_int(arg, &env.interval, 0, 10000);
		if (err) {
			warn("invalid interval: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'm':
		err = get_int(arg, &env.mode, 0, 1);
		if (err) {
			warn("invalid mode: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'o':
		env.redirect = true;
		strcpy(env.fpath, arg);
		break;
	case 't':
		err = get_int(arg, &env.timeout, 0, INT_MAX);
		if (err) {
			warn("invalid timeout :%s\n", arg);
			argp_usage(state);
		}
		break;
	case '4':
		if (inet_pton(AF_INET, arg, &env.raddr) < 0) {
			fprintf(stderr, "invalid remote address: %s\n", arg);
			argp_usage(state);
		}
		break;
	case '6':
		if (inet_pton(AF_INET6, arg, &env.raddr_v6) < 0) {
			fprintf(stderr, "invalid remote address: %s\n", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static void sig_int(int signo)
{
	exiting = 1;
	printf("exiting\n");
}

// static void timeout_handler(int time)
// {
// 	timeout = 1;
// 	printf("timeout\n");
// }

void set_timer()
{
	struct itimerval itv;
	itv.it_interval.tv_sec = 1;
	itv.it_interval.tv_usec = 0;
	itv.it_value.tv_sec = 0;
	itv.it_value.tv_usec = 0;
	if (env.timeout) {
		int err = setitimer(ITIMER_REAL, &itv, &oldtv);
		printf("set timer\n");
		if (err == -1)
			printf("set timer err\n");
	}
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *event = (struct event*)data;
	char sdata[1024];
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;

	if (event->af == AF_INET) {
		s.x4.s_addr = event->saddr_v4;
		d.x4.s_addr = event->daddr_v4;
	} else if (event->af == AF_INET6) {
		memcpy(&s.x6.s6_addr, event->saddr_v6, sizeof(s.x6.s6_addr));
		memcpy(&d.x6.s6_addr, event->daddr_v6, sizeof(d.x6.s6_addr));
	} else {
		warn("broken event: event->af=%d", event->af);
		return;
	}

	int res = sprintf(sdata, "%s:%d-%s:%d %d %d %lld %lld %lld %lld",
		   inet_ntop(event->af, &s, src, sizeof(src)), event->sport,
		   inet_ntop(event->af, &d, dst, sizeof(dst)), ntohs(event->dport),
		   event->af == AF_INET ? 4 : 6, event->close, 
		   event->bytes_sent, event->bytes_acked, event->bytes_retrans, event->span_ms);

	sprintf(sdata + res, "\n");
	
	if (env.redirect) {
		fprintf(fp, "%s", sdata);
		fflush(fp);
	} else {
		printf("%s", sdata);
	}
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void print_events(int perf_map_fd)
{
	struct perf_buffer *pb;
	int err;

	pb = perf_buffer__new(perf_map_fd, 128,
				  handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}
	
	while (!exiting && !timeout) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
		.args_doc = NULL,
	};
	struct tcpstat_bpf *skel;
	int i, err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	// err = ensure_core_btf(&open_opts);
	// if (err) {
	// 	fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
	// 	return 1;
	// }

	/* Open BPF application */
	skel = tcpstat_bpf__open_opts(&open_opts);
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	int p = 0;
	for (p = 0; p < 2; p++) {
		skel->rodata->filter_ports_len[p] = env.nports[p];
		for (i = 0; i < env.nports[p]; i++) {
			skel->rodata->filter_ports[p][i] = p == 0 ? env.ports[p][i] : ntohs(env.ports[p][i]);
		}
	}

	skel->rodata->mode = env.mode ? : 0;
	skel->rodata->sample_interval = env.interval ? : SAMPLE_INTERVAL;
	skel->rodata->targ_raddr = env.raddr;
	skel->rodata->targ_raddr_v6 = env.raddr_v6;

	/* ensure BPF program only handles write() syscalls from our process */
	//skel->bss->my_pid = getpid();

	/* Load & verify BPF programs */
	err = tcpstat_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = tcpstat_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	// if (signal(SIGALRM, timeout_handler) == SIG_ERR) {
	// 	warn("can't set signal handler: %s\n", strerror(errno));
	// 	err = 1;
	// 	goto cleanup;
	// }

	// set_timer();

	if((fp = fopen(env.fpath,"w")) == NULL) {
		printf("File %s cannot be opened\n", env.fpath);
	}
	else
		printf("File %s opened for writing\n", env.fpath);
	print_events(bpf_map__fd(skel->maps.events));

cleanup:
	fclose(fp);
	tcpstat_bpf__destroy(skel);
	//cleanup_core_btf(&open_opts);
	return -err;
}


