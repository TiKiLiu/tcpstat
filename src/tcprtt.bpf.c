// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "tcprtt.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

const volatile bool targ_laddr_hist = false;
const volatile bool targ_raddr_hist = false;
const volatile bool targ_show_ext = false;
const volatile __u32 targ_saddr = 0;
const volatile __u32 targ_daddr = 0;
const volatile bool targ_ms = false;

const volatile __u16 targ_ports[2][MAX_PORTS];
const volatile __u16 targ_ports_len[2] = {0, 0};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct hist);
} hists SEC(".maps");

static struct hist zero;

static __always_inline bool filter_port(struct sock *sk, int flag)
{
	u16 port, i;
	if (flag == 0)
		bpf_probe_read_kernel(&port, sizeof(port), &sk->__sk_common.skc_num);
	else
		bpf_probe_read_kernel(&port, sizeof(port), &sk->__sk_common.skc_dport);

	if (!targ_ports_len[flag])
		return true;

	for (i = 0; i < targ_ports_len[flag]; i++)
		if (port == targ_ports[flag][i])
			return true;
		
	return false;
}

static __always_inline bool filter_daddr(struct sock *sk)
{
	u32 raddr;
	BPF_CORE_READ_INTO(&raddr, sk, __sk_common.skc_daddr);
	if (targ_daddr && raddr != targ_daddr)
		return false;

	return true;
}

static __always_inline bool filter_saddr(struct sock *sk)
{
	u32 saddr;
	BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);

	if (targ_saddr && saddr != targ_saddr)
		return false;

	return true;
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk)
{
	const struct inet_sock *inet = (struct inet_sock *)(sk);
	struct tcp_sock *ts;
	struct hist *histp;
	u64 key, slot;
	u32 srtt;
	u16 sport, dport;

	bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
	bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

	if (!filter_port(sk, 0) || !filter_port(sk, 1))
		return 0;

	if (!filter_saddr(sk) || !filter_daddr(sk))
		return 0;

	if (targ_laddr_hist)
		key = sk->__sk_common.skc_rcv_saddr;
	else if (targ_raddr_hist)
		key = inet->sk.__sk_common.skc_daddr;
	else
		key = 0;

	histp = bpf_map_lookup_or_try_init(&hists, &key, &zero);
	if (!histp) {
		return 0;
	}

	ts = (struct tcp_sock *)(sk);
	srtt = BPF_CORE_READ(ts, srtt_us) >> 3;
	if (targ_ms)
		srtt /= 1000U;
	slot = log2l(srtt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);
	if (targ_show_ext) {
		__sync_fetch_and_add(&histp->latency, srtt);
		__sync_fetch_and_add(&histp->cnt, 1);
	}
	return 0;
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_kprobe, struct sock *sk)
{
	const struct inet_sock *inet = (struct inet_sock *)(sk);
	u32 srtt, saddr, daddr;
	struct tcp_sock *ts;
	struct hist *histp;
	u64 key, slot;
	u16 sport, dport;

	bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
	bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
	
	if (!filter_port(sk, 0) || !filter_port(sk, 1))
		return 0;

	if (!filter_saddr(sk) || !filter_daddr(sk))
		return 0;

	if (targ_laddr_hist)
		key = saddr;
	else if (targ_raddr_hist)
		key = daddr;
	else
		key = 0;
	
	histp = bpf_map_lookup_or_try_init(&hists, &key, &zero);
	if (!histp) {
		return 0;
	}

	ts = (struct tcp_sock *)(sk);
	bpf_probe_read_kernel(&srtt, sizeof(srtt), &ts->srtt_us);
	srtt >>= 3;
	if (targ_ms)
		srtt /= 1000U;
	slot = log2l(srtt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);
	if (targ_show_ext) {
		__sync_fetch_and_add(&histp->latency, srtt);
		__sync_fetch_and_add(&histp->cnt, 1);
	}
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock_info);
} currsocks SEC(".maps");

static struct sock_info d_sk_info;

static __always_inline int proc___tcp_transmit_skb(struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u16 sport, dport;
	u32 saddr, daddr;
	const struct inet_sock *inet = (struct inet_sock *)(sk);
	struct tcp_sock *tp = (struct tcp_sock *)(sk);
	struct sock_info * sk_infop;

	bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
	bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

	if (!filter_port(sk, 0) || !filter_port(sk, 1))
		return 0;
	
	if (!filter_saddr(sk) || !filter_daddr(sk))
		return 0;

	sk_infop = (struct sock_info* )bpf_map_lookup_elem(&currsocks, &pid);
	if (!sk_infop) {
		struct sock_info new_sk_info = {
			.sk = sk,
			.bytes_sent = BPF_CORE_READ(tp, bytes_sent),
			.data_segs_out = BPF_CORE_READ(tp, data_segs_out),
			.bytes_retrans = BPF_CORE_READ(tp, bytes_retrans),
			.total_retrans = BPF_CORE_READ(tp, total_retrans)
		};
		bpf_map_update_elem(&currsocks, &pid, &new_sk_info, BPF_ANY);
	}
	
	return 0;
}

static __always_inline int proc___tcp_transmit_skb_ret()
{
	u64 key;
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct hist *histp;
	struct sock_info *sk_infop;
	struct sock *sk;
	struct tcp_sock *tp;

	sk_infop = (struct sock_info *)bpf_map_lookup_elem(&currsocks, &pid);
	if (!sk_infop)
		return 0;

	sk = sk_infop->sk;
	tp = (struct tcp_sock *)sk;

	if (targ_laddr_hist)
		key = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	else if (targ_raddr_hist)
		key = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	else
		key = 0;

	histp = bpf_map_lookup_or_try_init(&hists, &key, &zero);
	if (!histp) {
		return 0;
	}

	__sync_fetch_and_add(&histp->bytes_sent, BPF_CORE_READ(tp, bytes_sent) - sk_infop->bytes_sent);
	__sync_fetch_and_add(&histp->data_segs_out, BPF_CORE_READ(tp, data_segs_out) - sk_infop->data_segs_out);

	bpf_map_delete_elem(&currsocks, &pid);
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock_info);
} recurrsocks SEC(".maps");

static __always_inline int proc_tcp_retransmit_skb(struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u16 sport, dport;
	u32 saddr, daddr;
	const struct inet_sock *inet = (struct inet_sock *)(sk);
	struct tcp_sock *tp = (struct tcp_sock *)(sk);
	struct sock_info * sk_infop;

	bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
	bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

	if (!filter_port(sk, 0) || !filter_port(sk, 1))
		return 0;
	
	if (!filter_saddr(sk) || !filter_daddr(sk))
		return 0;

	sk_infop = (struct sock_info* )bpf_map_lookup_elem(&recurrsocks, &pid);
	if (!sk_infop) {
		struct sock_info new_sk_info = {
			.sk = sk,
			.bytes_sent = BPF_CORE_READ(tp, bytes_sent),
			.data_segs_out = BPF_CORE_READ(tp, data_segs_out),
			.bytes_retrans = BPF_CORE_READ(tp, bytes_retrans),
			.total_retrans = BPF_CORE_READ(tp, total_retrans)
		};
		bpf_map_update_elem(&recurrsocks, &pid, &new_sk_info, BPF_ANY);
	}

	return 0;
}

static __always_inline int proc_tcp_retransmit_skb_ret()
{
	u64 key;
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct hist *histp;
	struct sock_info *sk_infop;
	struct sock *sk;
	struct tcp_sock *tp;
	sk_infop = (struct sock_info *)bpf_map_lookup_elem(&recurrsocks, &pid);
	if (!sk_infop)
		return 0;

	sk = sk_infop->sk;
	tp = (struct tcp_sock *)sk;

	if (targ_laddr_hist)
		key = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	else if (targ_raddr_hist)
		key = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	else
		key = 0;

	histp = bpf_map_lookup_or_try_init(&hists, &key, &zero);
	if (!histp) {
		return 0;
	}

	__sync_fetch_and_add(&histp->bytes_retrans, BPF_CORE_READ(tp, bytes_retrans) - sk_infop->bytes_retrans);
	__sync_fetch_and_add(&histp->total_retrans, BPF_CORE_READ(tp, total_retrans) - sk_infop->total_retrans);

	bpf_map_delete_elem(&recurrsocks, &pid);
	return 0;
}

SEC("fentry/__tcp_transmit_skb")
int BPF_PROG(tcp_transmit, struct sock *sk)
{
	return proc___tcp_transmit_skb(sk);
}

SEC("fexit/__tcp_transmit_skb")
int BPF_PROG(tcp_transmit_ret)
{
	return proc___tcp_transmit_skb_ret();
}

SEC("fentry/__tcp_retransmit_skb")
int BPF_PROG(tcp_retransmit, struct sock *sk)
{
	return proc_tcp_retransmit_skb(sk);
}

SEC("fexit/__tcp_retransmit_skb")
int BPF_PROG(tcp_retransmit_ret)
{
	return proc_tcp_retransmit_skb_ret();
}

SEC("kprobe/__tcp_transmit_skb")
int BPF_PROG(tcp_transmit_kprobe, struct sock *sk)
{
	return proc___tcp_transmit_skb(sk);
}

SEC("kretprobe/__tcp_transmit_skb")
int BPF_PROG(tcp_transmit_ret_kprobe)
{
	return proc___tcp_transmit_skb_ret();
}

SEC("kprobe/__tcp_retransmit_skb")
int BPF_PROG(tcp_retransmit_kprobe, struct sock *sk)
{
	return proc_tcp_retransmit_skb(sk);
}

SEC("kretprobe/__tcp_retransmit_skb")
int BPF_PROG(tcp_retransmit_ret_kprobe)
{
	return proc_tcp_retransmit_skb_ret();
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
