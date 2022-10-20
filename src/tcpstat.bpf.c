#include <vmlinux.h>
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_core_read.h>     /* for BPF CO-RE helpers */
#include <bpf/bpf_tracing.h>
#include "tcpstat.h"

#define AF_INET 2
#define AF_INET6 10

enum MODE {
	STREAM,
	REALTIME	
};

const volatile int filter_ports[2][MAX_PORTS];
const volatile int filter_ports_len[2] = {0, 0};
const volatile int mode = 0;
const volatile int sample_interval = 1000;

const volatile __u32 targ_raddr = 0;
const volatile __u32 targ_laddr = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, struct tcp_info_t);
} tcp_streams SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} tcp_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock *);
} currsocks SEC(".maps");

static __always_inline bool filter_raddr(struct sock *sk)
{
	u16 family;
	bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);

	if (!targ_raddr)
		return true;

	u32 raddr;
	BPF_CORE_READ_INTO(&raddr, sk, __sk_common.skc_daddr);
	if (raddr == targ_raddr)
		return true;

	return false;
}

static __always_inline bool filter_laddr(struct sock *sk)
{
	u32 laddr; 

	if (!targ_laddr)
		return true;
	BPF_CORE_READ_INTO(&laddr, sk, __sk_common.skc_rcv_saddr);
	if (laddr == targ_laddr)
		return true;

	return false;
}

static __always_inline bool filter_port(__u16 port, int flag)
{
	int i;

	if (!filter_ports_len[flag])
		return true;

	for (i = 0; i < filter_ports_len[flag] && i < MAX_PORTS; i++) {
		if (port == filter_ports[flag][i])
			return true;
	}

	return false;
}

static __always_inline int tcp_start(struct sock *sk)
{
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	struct tcp_info_t *info = bpf_map_lookup_elem(&tcp_streams, &sk);

	if (!info) {
		struct tcp_info_t new_info = {
			.data_segs_out = BPF_CORE_READ(tp, data_segs_out),
			.bytes_acked = BPF_CORE_READ(tp, bytes_acked),
			.bytes_sent = BPF_CORE_READ(tp, bytes_sent),
			.bytes_received = BPF_CORE_READ(tp, bytes_received),
			.bytes_retrans = BPF_CORE_READ(tp, bytes_retrans),
			.total_retrans = BPF_CORE_READ(tp, total_retrans),
			.min_rtt_ms = BPF_CORE_READ(tp, rtt_min.s[0].v) >> 3 / USEC_PER_MSEC,
		};
		new_info.sample_tstamp = bpf_ktime_get_ns() / NSEC_PER_MSEC;
		bpf_map_update_elem(&tcp_streams, &sk, &new_info, BPF_ANY);
	}
	return 0;
}

static void tcp_info_update(struct sock *sk, struct tcp_info_t *info)
{
	struct tcp_sock *tp = (struct tcp_sock *)sk;

	info->data_segs_out = BPF_CORE_READ(tp, data_segs_out);
	info->bytes_acked = BPF_CORE_READ(tp, bytes_acked);
	info->bytes_sent = BPF_CORE_READ(tp, bytes_sent);
	info->bytes_received = BPF_CORE_READ(tp, bytes_received);
	info->bytes_retrans = BPF_CORE_READ(tp, bytes_retrans);
	info->sample_tstamp = bpf_ktime_get_ns() / NSEC_PER_MSEC;

	info->min_rtt_ms = (BPF_CORE_READ(tp, rtt_min.s[0].v) >> 3) / USEC_PER_MSEC;
}

static __always_inline void tcp_event_report(struct pt_regs *ctx, struct sock *sk, struct tcp_info_t *info, u16 family)
{
	struct tcp_event_t event = {};
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	u64 curr_ts = bpf_ktime_get_ns() / NSEC_PER_MSEC;

	event.af = family;
	BPF_CORE_READ_INTO(&event.saddr_v4, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&event.daddr_v4, sk, __sk_common.skc_daddr);

	BPF_CORE_READ_INTO(&event.sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&event.dport, sk, __sk_common.skc_dport);

	event.data_segs_out = BPF_CORE_READ(tp, data_segs_out) - info->data_segs_out;
	event.bytes_sent = BPF_CORE_READ(tp, bytes_sent) - info->bytes_sent;
	event.bytes_received = BPF_CORE_READ(tp, bytes_received) - info->bytes_received;
	event.bytes_acked = BPF_CORE_READ(tp, bytes_acked) - info->bytes_acked;
	event.bytes_retrans = BPF_CORE_READ(tp, bytes_retrans) - info->bytes_retrans;
	event.total_retrans = BPF_CORE_READ(tp, total_retrans) - info->total_retrans;

	event.min_rtt_ms = info->min_rtt_ms;
	event.span_ms = curr_ts - info->sample_tstamp;

	bpf_perf_event_output(ctx, &tcp_events, BPF_F_CURRENT_CPU,
				  &event, sizeof(event));

	tcp_info_update(sk, info);
	info->last_report_tstamp = curr_ts;
}

static __always_inline int proc_tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
	__u16 lport, dport, family;

	bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
	bpf_probe_read_kernel(&lport, sizeof(lport), &sk->__sk_common.skc_num);
	bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

	if (!filter_laddr(sk))
		return 0;

	if (!filter_raddr(sk))
		return 0;

	if (!filter_port(lport, 0))
		return 0;

	if (!filter_port(dport, 1))
		return 0;

	if (state < TCP_FIN_WAIT1) {
		tcp_start(sk);
	}

	if (state != TCP_CLOSE)
		return 0;

	struct tcp_info_t *info = bpf_map_lookup_elem(&tcp_streams, &sk);
	if (!info)
		return 0;

	tcp_event_report(ctx, sk, info, family);

	bpf_map_delete_elem(&tcp_streams, &sk);
	return 0;
}

static __always_inline int proc_tcp_ack(struct sock *sk, const struct sk_buff *skb, int flag)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u16 lport, dport;
	bpf_probe_read_kernel(&lport, sizeof(lport), &sk->__sk_common.skc_num);
	bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

	if (!filter_laddr(sk))
		return 0;

	if (!filter_raddr(sk))
		return 0;

	if (!filter_port(lport, 0))
		return 0;

	if (!filter_port(dport, 1))
		return 0;

	struct tcp_info_t *info = bpf_map_lookup_elem(&tcp_streams, &sk);
	if (!info)
		tcp_start(sk);
	
	bpf_map_update_elem(&currsocks, &pid, &sk, BPF_ANY);

	return 0;
}

static __always_inline int proc_tcp_ack_ret(struct pt_regs *ctx, int ret)
{
		u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct sock **skp = bpf_map_lookup_elem(&currsocks, &pid);
	
	if (!skp)
		return 0;
	
	struct sock *sk = *skp;
	struct inet_sock *inet = (struct inet_sock *)sk;

	struct tcp_info_t *info = bpf_map_lookup_elem(&tcp_streams, &sk);
	if (!info)
		goto OUT;

	u16 family;
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

	u64 curr_ts = bpf_ktime_get_ns() / NSEC_PER_MSEC;
	u64 tcp_last_report = info->last_report_tstamp;
	if (mode && curr_ts - sample_interval >= tcp_last_report) {
		tcp_event_report(ctx, sk, info, family);
	}

OUT:
	bpf_map_delete_elem(&currsocks, &sk);
	return 0;
}

SEC("fentry/tcp_set_state")
int BPF_PROG(tcp_set_state, struct sock *sk, int state)
{
	return proc_tcp_set_state((struct pt_regs *)ctx, sk, state);
}

SEC("fentry/tcp_ack")
int BPF_PROG(tcp_ack, struct sock *sk, const struct sk_buff *skb, int flag)
{
	return proc_tcp_ack(sk, skb, flag);
}

SEC("fexit/tcp_ack")
int BPF_PROG(tcp_ack_ret, int ret)
{
	return proc_tcp_ack_ret((struct pt_regs *)ctx, ret);
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(tcp_set_state_kprobe, struct sock *sk, int state)
{
	return proc_tcp_set_state((struct pt_regs *)ctx, sk, state);
}

SEC("kprobe/tcp_ack")
int BPF_KPROBE(tcp_ack_kprobe, struct sock *sk, const struct sk_buff *skb, int flag)
{
	return proc_tcp_ack(sk, skb, flag);
}

SEC("kretprobe/tcp_ack")
int BPF_KRETPROBE(tcp_ack_kretprobe, int ret)
{
	return proc_tcp_ack_ret((struct pt_regs *)ctx, ret);
}

char LICENSE[] SEC("license") = "GPL";