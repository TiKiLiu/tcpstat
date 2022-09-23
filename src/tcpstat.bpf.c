#include <vmlinux.h>
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_core_read.h>     /* for BPF CO-RE helpers */
#include <bpf/bpf_tracing.h>
#include "tcpstat.h"

const volatile int filter_ports[MAX_PORTS];
const volatile int filter_ports_len = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, struct data_t *);
} ipv4_streams SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline bool filter_port(__u16 port)
{
	int i;

	if (filter_ports_len == 0)
		return true;

	for (i = 0; i < filter_ports_len && i < MAX_PORTS; i++) {
		if (port == filter_ports[i])
			return true;
	}
	return false;
}

static __always_inline int tcp_start(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct data_t *data = bpf_map_lookup_elem(&ipv4_streams, &sk);
	if (!data) {
		u32 delivered = BPF_CORE_READ(tp, delivered);
		struct data_t new_data = {
			.cwnd_limited_cnt = 0,
			.write_xmit_cnt = 0,
		};
		new_data.start_tstamp = bpf_ktime_get_ns() / NSEC_PER_MSEC;
		new_data.last_report_tstamp = bpf_ktime_get_ns() / NSEC_PER_MSEC;
        bpf_map_update_elem(&ipv4_streams, &sk, &new_data, BPF_ANY);
	}
	return 0;
}

static __always_inline void ipv4_event_report(struct pt_regs *ctx, struct sock *sk, struct data_t *data, u32 closed)
{
	struct event event = {};
    struct inet_sock *inet = inet_sk(sk);
    struct tcp_sock *tp = tcp_sk(sk);
	u64 curr_ts = bpf_ktime_get_ns() / NSEC_PER_MSEC;

    event.af = AF_INET;
    BPF_CORE_READ_INTO(&event.sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&event.dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&event.saddr_v4, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&event.daddr_v4, sk, __sk_common.skc_daddr);
    event.dport = ntohs(event.dport);

	event.bytes_sent = BPF_CORE_READ(tp, bytes_sent);
	event.bytes_acked = BPF_CORE_READ(tp, bytes_acked);
	event.bytes_retrans = BPF_CORE_READ(tp, bytes_retrans);

	event.data_segs_out = BPF_CORE_READ(tp, data_segs_out);
	event.retrans_out = BPF_CORE_READ(tp, retrans_out);

	event.write_xmit_cnt = data->write_xmit_cnt;
	event.cwnd_limited_cnt = data->cwnd_limited_cnt;

	event.span_ms = curr_ts - data->start_tstamp;
	event.close = closed;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));
	ipv4_data_reset(data);
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(enter_tcp_set_state, struct sock *sk, int state)
{
    u16 lport, dport, family;
    struct inet_sock *inet = inet_sk(sk);
    
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    BPF_CORE_READ_INTO(&lport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

    if(!filter_port(lport))
        return 0;

	if (state < TCP_FIN_WAIT1) {
		tcp_start(sk);
	}

	if (state != TCP_CLOSE)
		return 0;

	struct data_t *data = bpf_map_lookup_elem(&ipv4_streams, &sk);
	if (!data)
		return 0;

    if (family == AF_INET)
	    ipv4_event_report(ctx, sk, data, 1);

    bpf_map_delete_elem(&ipv4_streams, &sk);
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock *);
} currsocks SEC(".maps");

SEC("kprobe/tcp_ack")
int BPF_KPROBE(tcp_ack, struct sock *sk, const struct sk_buff *skb, int flag)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct data_t *data = bpf_map_lookup_elem(&ipv4_streams, &sk);
    if (!data)
        return 0;
    
    bpf_map_update_elem(&currsocks, &pid, &sk, BPF_ANY);

    return 0;
}

SEC("kretprobe/tcp_ack")
int BPF_KRETPROBE(tcp_ack_ret, int ret)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sock **skp = bpf_map_lookup_elem(&currsocks, &pid);
    
    if (!skp)
        return 0;
    
    struct sock *sk = *skp;
    struct inet_sock *inet = inet_sk(sk);

    struct data_t *data = bpf_map_lookup_elem(&currsocks, &sk);
    if (!data)
        goto OUT;

	u16 family;
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

    u64 curr_ts = bpf_ktime_get_ns() / NSEC_PER_MSEC;
    u64 last_report = data->last_report_tstamp;
    if (curr_ts - INTERVAL >= last_report) {
        if (family == AF_INET)
		    ipv4_event_report(ctx, sk, data, 0);
	}

OUT:
    bpf_map_delete_elem(&currsocks, &sk);
    return 0;
}