/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCPRTT_H
#define __TCPRTT_H

#define MAX_SLOTS	27
#define MAX_PORTS	64
#define MAX_ENTRIES	10240

struct hist {
	__u64 latency;
	__u64 cnt;
	__u32 slots[MAX_SLOTS];
	__u64 data_segs_out;
	__u64 bytes_sent;
	__u64 bytes_retrans;
	__u64 total_retrans;
	__u64 bytes_received;
};

struct sock_info {
	__u64 data_segs_out;
	__u64 bytes_sent;
	__u64 bytes_retrans;
	__u64 total_retrans;
	struct sock *sk;
};

struct tx_info {
	__u64 data_segs_out;
	__u64 bytes_sent;
	__u64 bytes_retrans;
	__u64 total_retrans;
};

#endif /* __TCPRTT_H */