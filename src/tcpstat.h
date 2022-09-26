#ifndef __TCPLIFE_H_
#define __TCPLIFE_H_
// #include <uapi/linux/ptrace.h>
// #include <net/sock.h>
// #include <net/tcp_states.h>
// #include <net/tcp.h>


/* The maximum number of items in maps */
#define MAX_ENTRIES 8192
#define INTERVAL 1000

/* The maximum number of ports to filter */
#define MAX_PORTS 64
#define NSEC_PER_MSEC 1000000

struct event {
	__u32 af;
	union {
		__u32 saddr_v4;
		__u8 saddr_v6[16];
	};
	
	union {
		__u32 daddr_v4;
		__u8 daddr_v6[16];
	};
	__u16 sport;
	__u16 dport;

	__u64 bytes_sent;
	__u64 bytes_acked;
	__u64 bytes_retrans;
	__u64 data_segs_out;
	__u64 retrans_out;
	__u64 cwnd_limited_cnt;
	__u64 write_xmit_cnt;
	__u64 span_ms;
	__u32 close;
};

struct data_t {
	__u64 start_tstamp;

	__u64 cwnd_limited_cnt;
	__u64 write_xmit_cnt;
	__u64 last_report_tstamp;
};

struct sent_info_t {
	__u32 snd_nxt;
	struct sock *sk;
};

#endif