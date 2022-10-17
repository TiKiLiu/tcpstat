/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCPRETRANS_H
#define __TCPRETRANS_H

struct tx_info {
	__u64 bytes_sent;
	__u64 bytes_retrans;
	__u64 data_seg_out;
    __u64 total_retrans;
};

#endif /* __TCPRETRANS_H */
