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
#ifndef __NSS_UDP_ST_DRV_H
#define __NSS_UDP_ST_DRV_H

#ifdef __KERNEL__ /* only kernel will use. */
#include <linux/sizes.h>
#endif

#define NSS_UDP_ST_IFNAMSZ	24
#define NSS_UDP_ST_IPNAMSZ	40
#define NSS_UDP_ST_MODESZ	24

#ifdef __KERNEL__ /* only kernel will use. */
#define NSS_UDP_ST_FLAG_IPV4	0x1
#define NSS_UDP_ST_FLAG_IPV6	0x2
#endif

/*
 * NSS UDP speedtest ioctl parameters
 */
#define NSS_UDP_ST_IOCTL_MAGIC	'n'
#define NSS_UDP_ST_IOCTL_INIT	_IOW(NSS_UDP_ST_IOCTL_MAGIC, 0, struct nss_udp_st_param* )
#define NSS_UDP_ST_IOCTL_START_TX	_IOW(NSS_UDP_ST_IOCTL_MAGIC, 1, int)
#define NSS_UDP_ST_IOCTL_START_RX	_IOW(NSS_UDP_ST_IOCTL_MAGIC, 2, int)
#define NSS_UDP_ST_IOCTL_STOP	_IO(NSS_UDP_ST_IOCTL_MAGIC, 3)
#define NSS_UDP_ST_DEV	"/dev/nss_udp_st"

#ifdef __KERNEL__ /* only kernel will use. */
#define NSS_UDP_ST_MAX_HEADROOM	32	/* Maximum headroom needed */
#define NSS_UDP_ST_MAX_TAILROOM	32	/* Maximum tailroom needed */
#define NSS_UDP_ST_BUFFER_SIZE_MAX	1500	/* 1500 bytes */
#define NSS_UDP_ST_RATE_MAX	20000000000	/* 20 Gbps */

extern struct nss_udp_st nust;
extern struct delayed_work nss_udp_st_tx_delayed_work;
extern struct workqueue_struct *work_queue;
extern void nss_udp_st_update_stats(size_t pkt_size);
extern uint64_t nss_udp_st_tx_num_pkt;
extern struct net_device *nust_dev;
#endif

/*
 * nss_udp_st_rule
 *  NSS UDP speedtest rules parameters
 */
enum nss_udp_st_rule {
	NSS_UDP_ST_SIP,	/* source IP */
	NSS_UDP_ST_DIP,	/* destination IP */
	NSS_UDP_ST_SPORT,	/* source port */
	NSS_UDP_ST_DPORT,	/* destination port */
	NSS_UDP_ST_FLAGS,	/* IP version flag */
};

/*
 * nss_udp_st_stats_stats
 *	time stats
 */
enum nss_udp_st_stats_time {
	NSS_UDP_ST_STATS_TIME_START,	/* Start time of the test */
	NSS_UDP_ST_STATS_TIME_CURRENT,	/* Current time of the running test */
	NSS_UDP_ST_STATS_TIME_ELAPSED,	/* Elapsed time of the current test */
	NSS_UDP_ST_STATS_TIME_MAX		/* Maximum timer statistics type */
};

/*
 * nss_udp_st_error
 *	error stats
 */
enum nss_udp_st_error {
	NSS_UDP_ST_ERROR_NONE,			/* no error */
	NSS_UDP_ST_ERROR_INCORRECT_RATE,	/* incorrect rate */
	NSS_UDP_ST_ERROR_INCORRECT_BUFFER_SIZE,	/* incorrect buffer size */
	NSS_UDP_ST_ERROR_MEMORY_FAILURE,		/* Memory allocation failed */
	NSS_UDP_ST_ERROR_INCORRECT_IP_VERSION,	/* Incorrect IP version */
	NSS_UDP_ST_ERROR_PACKET_DROP,	/* Packet Drop */
	NSS_UDP_ST_ERROR_MAX			/* Maximum error statistics type */
};

/*
 * nss_udp_st_type
 *	tx/rx flags
 */
enum nss_udp_st_type {
	NSS_UDP_ST_TX,	/* Tx 0 */
	NSS_UDP_ST_RX,	/* Rx 1 */
};

/*
 * nss_udp_st_param
 *  config parameters for Tx test
 */
struct nss_udp_st_param {
	uint32_t rate;		/* target rate in Mbps */
	uint32_t buffer_sz;	/* buffer size of each packet */
	uint32_t dscp;		/* dscp flag for tx packet */
	char net_dev[NSS_UDP_ST_IFNAMSZ];	/* net device interface */
};

/*
 * nss_udp_st_opt
 *  5 tuple config parameters
 */
struct nss_udp_st_opt {
	uint16_t sport;			/* source port */
	uint16_t dport;			/* destination port */
	uint16_t ip_version;	/* ip version flag */
	char sip[NSS_UDP_ST_IPNAMSZ];	/* source ip string */
	char dip[NSS_UDP_ST_IPNAMSZ];	/* dest ip string */
};

#ifdef __KERNEL__ /* only kernel will use. */
/*
 * nss_udp_st_mode
 *  start/stop flags
 */
enum nss_udp_st_mode {
	NSS_UDP_ST_STOP,	/* Stop 0 */
	NSS_UDP_ST_START,	/* Start 1 */
};

/*
 * nss_udp_st_ip
 *  ipv4/ipv6 params
 */
struct nss_udp_st_ip {
	union {
		uint32_t ipv4;	/* IPv4 address. */
		uint32_t ipv6[4];	/* IPv6 address. */
	} ip;
};

/*
 * nss_udp_st_pkt_stats
 *  packet stats
 */
struct nss_udp_st_pkt_stats {
	atomic_long_t tx_packets;	/* Number of packets transmitted */
	atomic_long_t tx_bytes;	/* Number of bytes transmitted */
	atomic_long_t rx_packets;	/* Number of packets received */
	atomic_long_t rx_bytes;	/* Number of bytes received */
};
/*
 * nss_udp_st_stats
 *	stats for tx/rx test
 */
struct nss_udp_st_stats {
	struct nss_udp_st_pkt_stats p_stats;			/* Packet statistics */
	atomic_long_t timer_stats[NSS_UDP_ST_STATS_TIME_MAX];	/* Time statistics */
	atomic_long_t errors[NSS_UDP_ST_ERROR_MAX];		/* Error statistics */
	bool first_pkt;					/* First packet flag */
};

/*
 * nss_udp_st_rules
 *	config rules configured for tx/rx test
 */
struct nss_udp_st_rules {
	struct list_head list;		/* kernel’s list structure */
	struct nss_udp_st_ip sip;		/* source ip */
	struct nss_udp_st_ip dip;		/* dest ip */
	uint16_t sport;			/* source port */
	uint16_t dport;			/* dest port */
	uint16_t flags;			/* version of IP address */
	uint8_t dst_mac[ETH_ALEN];		/* dest mac */
};

/*
 * nss_udp_st
 *	config/rules/stats for tx/rx test
 */
struct nss_udp_st {
	struct nss_udp_st_param config;	/* config params for tx */
	struct nss_udp_st_rules rules;	/* database for config rules */
	struct nss_udp_st_stats stats;	/* result statistics */
	uint32_t rule_count;		/* no of rules configured */
	uint64_t time;			/* duration of test */
	bool mode;			/* start =0; stop=1 */
	bool dir;			/* tx=0; rx=1 */
};
#endif

#endif /*NSS_UDP_ST_H*/
