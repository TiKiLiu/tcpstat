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

#define AF_INET 2

struct event {
	__u32 af;
	union {
		__u32 saddr_v4;
		__u8 saddr_v6[16];
	};
	
	union {
		__u32 daddr_v4;
		__u8 daddr_v6[16];
	}
	u16 sport;
	u16 dport;

	u64 bytes_sent;
	u64 bytes_acked;
	u64 bytes_retrans;
	u64 data_segs_out;
	u64 retrans_out;
	u64 cwnd_limited_cnt;
	u64 write_xmit_cnt;
	u64 span_ms;
	u32 close;
};

struct data_t {
	u64 start_tstamp;

	u64 cwnd_limited_cnt;
	u64 write_xmit_cnt;
	u64 last_report_tstamp;
};

struct sent_info_t {
	u32 snd_nxt;
	struct sock *sk;
};

static void ipv4_data_reset(struct data_t *data)
{
	data->write_xmit_cnt = 0;
	data->cwnd_limited_cnt = 0;
	data->last_report_tstamp = bpf_ktime_get_ns() / NSEC_PER_MSEC;
}

#endif