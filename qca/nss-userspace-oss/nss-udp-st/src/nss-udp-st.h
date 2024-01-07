/*
 **************************************************************************
 * Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

#ifndef __NSS_UDP_ST_H
#define __NSS_UDP_ST_H

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdatomic.h>
#include "nss_udp_st_drv.h"

/*
 * NSS UDP speedtest path parameters
 */
#define NSS_UDP_ST_LOG "/tmp/nss-udp-st"
#define NSS_UDP_ST_TX_STATS "/tmp/nss-udp-st/tx_stats"
#define NSS_UDP_ST_RX_STATS "/tmp/nss-udp-st/rx_stats"
#define NSS_UDP_ST_RULES "/tmp/nss-udp-st/rules"

/*
 * nss_udp_st_cfg
 *  NSS UDP speedtest common parameters
 */
struct nss_udp_st_cfg {
	long time;                      /* time for speedtest */
	int handle;                     /* handle for NSS_UDP_ST_DEV */
	int type;                       /* type ( tx/rx ) */
	char mode[NSS_UDP_ST_MODESZ];   /* mode for speedtest */
};

/*
 * nss_udp_st_pkt_stats
 *  packet stats
 */
struct nss_udp_st_pkt_stats {
	atomic_llong tx_packets;	/* Number of packets transmitted */
	atomic_llong tx_bytes;		/* Number of bytes transmitted */
	atomic_llong rx_packets;	/* Number of packets received */
	atomic_llong rx_bytes;		/* Number of bytes received */
};

/*
 * nss_udp_st_stat
 *  stats for tx/rx test
 */
struct nss_udp_st_stat {
	struct nss_udp_st_pkt_stats p_stats;				/* Packet statistics */
	atomic_llong timer_stats[NSS_UDP_ST_STATS_TIME_MAX];	/* Time statistics */
	atomic_llong errors[NSS_UDP_ST_ERROR_MAX];				/* Error statistics */
};

#endif /*__NSS_UDP_ST_H*/
