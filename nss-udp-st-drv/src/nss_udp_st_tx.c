/*
 **************************************************************************
 * Copyright (c) 2022-2023 Qualcomm Innovation Center, Inc. All rights reserved.
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

#include <linux/list.h>
#include <linux/string.h>
#include <linux/hrtimer.h>
#include <net/act_api.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <linux/if_vlan.h>
#include <linux/if_pppox.h>
#include <net/ip6_checksum.h>
#include "nss_udp_st_public.h"

int tx_timer_flag;
static ktime_t kt;
static struct hrtimer tx_hr_timer;
static enum hrtimer_restart tx_hr_restart = HRTIMER_NORESTART;
static struct vlan_hdr vh;
static struct net_device *xmit_dev;
static struct pppoe_opt info;

/*
 * nss_udp_st_generate_ipv4_hdr()
 *	generate ipv4 header
 */
static inline void nss_udp_st_generate_ipv4_hdr(struct iphdr *iph, uint16_t ip_len, struct nss_udp_st_rules *rules)
{
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = nust.config.dscp;
	iph->tot_len = htons(ip_len);
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;
	iph->saddr = htonl(rules->sip.ip.ipv4);
	iph->daddr = htonl(rules->dip.ip.ipv4);
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

/*
 * nss_udp_st_generate_ipv6_hdr()
 *	generate ipv6 header
 */
static inline void nss_udp_st_generate_ipv6_hdr(struct ipv6hdr *ipv6h, uint16_t ip_len, struct nss_udp_st_rules *rules)
{
	struct in6_addr addr;

	ipv6h->version = 6;
	memset(&ipv6h->flow_lbl, 0, sizeof(ipv6h->flow_lbl));
	ipv6h->nexthdr = IPPROTO_UDP;
	ipv6h->payload_len = htons(ip_len - sizeof(*ipv6h));
	ipv6h->hop_limit = 64;
	nss_udp_st_get_ipv6_addr_hton(rules->sip.ip.ipv6, addr.s6_addr32);
	memcpy(ipv6h->saddr.s6_addr32, addr.s6_addr32, sizeof(ipv6h->saddr.s6_addr32));
	nss_udp_st_get_ipv6_addr_hton(rules->dip.ip.ipv6, addr.s6_addr32);
	memcpy(ipv6h->daddr.s6_addr32, addr.s6_addr32, sizeof(ipv6h->daddr.s6_addr32));
}

/*
 * nss_udp_st_generate_udp_hdr()
 *	generate udp header
 */
static void nss_udp_st_generate_udp_hdr(struct udphdr *uh, uint16_t udp_len, struct nss_udp_st_rules *rules)
{

	uh->source = htons(rules->sport);
	uh->dest = htons(rules->dport);
	uh->len = htons(udp_len);

	if (rules->flags & NSS_UDP_ST_FLAG_IPV4) {
		uh->check = csum_tcpudp_magic(rules->sip.ip.ipv4, rules->dip.ip.ipv4, udp_len, IPPROTO_UDP,
		csum_partial(uh, udp_len, 0));
	} else if (rules->flags & NSS_UDP_ST_FLAG_IPV6) {
		struct in6_addr saddr;
		struct in6_addr daddr;

		nss_udp_st_get_ipv6_addr_hton(rules->sip.ip.ipv6, saddr.s6_addr32);
		nss_udp_st_get_ipv6_addr_hton(rules->dip.ip.ipv6, daddr.s6_addr32);

		uh->check = csum_ipv6_magic(&saddr, &daddr, udp_len, IPPROTO_UDP,
		csum_partial(uh, udp_len, 0));
	} else {
		atomic_long_inc(&nust.stats.errors[NSS_UDP_ST_ERROR_INCORRECT_IP_VERSION]);
		return;
	}

	if (uh->check == 0) {
		uh->check = CSUM_MANGLED_0;
	}
}

/*
 * nss_udp_st_generate_eth_hdr()
 *	generate L2 header
 */
static inline void nss_udp_st_generate_eth_hdr(struct sk_buff *skb, const uint8_t *src_mac, uint8_t *dst_mac)
{
	struct ethhdr *eh = (struct ethhdr *)skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);

	eh->h_proto = skb->protocol;
	memcpy(eh->h_source, src_mac, ETH_ALEN);
	memcpy(eh->h_dest, dst_mac, ETH_ALEN);
}

/*
 * nss_udp_st_generate_vlan_hdr
 *	Generate VLAN header
 */
static void nss_udp_st_generate_vlan_hdr(struct sk_buff *skb, struct net_device *ndev)
{
	struct vlan_hdr *vhdr;

	skb_push(skb, VLAN_HLEN);
	vhdr = (struct vlan_hdr *)skb->data;
	vhdr->h_vlan_TCI = htons(vh.h_vlan_TCI);
	vhdr->h_vlan_encapsulated_proto = skb->protocol;
	skb->protocol = htons(vh.h_vlan_encapsulated_proto);
}

/*
 * nss_udp_st_generate_pppoe_hdr
 *	Generate PPPoE header
 */
static void nss_udp_st_generate_pppoe_hdr(struct sk_buff *skb, uint16_t ppp_protocol)
{
	struct pppoe_hdr *ph;
	unsigned char *pp;
	unsigned int data_len;

	/*
	 * Insert the PPP header protocol
	 */
	pp = skb_push(skb, 2);
	put_unaligned_be16(ppp_protocol, pp);

	data_len = skb->len;

	ph = (struct pppoe_hdr *)skb_push(skb, sizeof(*ph));
	skb_reset_network_header(skb);

	/*
	 * Headers in skb will look like in below sequence
	 *	| PPPoE hdr(6 bytes) | PPP hdr (2 bytes) | L3 hdr |
	 *
	 *	The length field in the PPPoE header indicates the length of the PPPoE payload which
	 *	consists of a 2-byte PPP header plus a skb->len.
	 */
	ph->ver = 1;
	ph->type = 1;
	ph->code = 0;
	ph->sid = (uint16_t)info.pa.sid;
	ph->length = htons(data_len);

	skb->protocol = htons(ETH_P_PPP_SES);
}

/*
 * nss_udp_st_tx_packets()
 *	allocate, populate and send tx packet
 */
static void nss_udp_st_tx_packets(struct net_device *ndev, struct nss_udp_st_rules *rules)
{
	struct sk_buff *skb;
	struct udphdr *uh;
	struct iphdr *iph;
	struct ipv6hdr *ipv6h;
	size_t align_offset;
	size_t skb_sz;
	size_t pkt_sz;
	uint16_t ip_len;
	uint16_t udp_len;
	unsigned char *data;
	uint16_t ppp_protocol;

	pkt_sz = nust.config.buffer_sz;
	ip_len = pkt_sz;

	if (rules->flags & NSS_UDP_ST_FLAG_IPV4) {
		udp_len = pkt_sz - sizeof(*iph);
	} else if (rules->flags & NSS_UDP_ST_FLAG_IPV6) {
		udp_len = pkt_sz - sizeof(*ipv6h);
	} else {
		atomic_long_inc(&nust.stats.errors[NSS_UDP_ST_ERROR_INCORRECT_IP_VERSION]);
		return;
	}

	skb_sz = NSS_UDP_ST_MIN_HEADROOM + pkt_sz + sizeof(struct ethhdr) + NSS_UDP_ST_MIN_TAILROOM + SMP_CACHE_BYTES;

	skb = dev_alloc_skb(skb_sz);
	if (!skb) {
		atomic_long_inc(&nust.stats.errors[NSS_UDP_ST_ERROR_MEMORY_FAILURE]);
		return;
	}

	align_offset = PTR_ALIGN(skb->data, SMP_CACHE_BYTES) - skb->data;
	skb_reserve(skb, NSS_UDP_ST_MAX_HEADROOM + align_offset + sizeof(uint16_t));

	/*
	 * populate udp header
	 */
	skb_push(skb, sizeof(*uh));
	skb_reset_transport_header(skb);
	uh = udp_hdr(skb);
	nss_udp_st_generate_udp_hdr(uh, udp_len, rules);

	/*
	 * populate ipv4 or ipv6  header
	 */
	if (rules->flags & NSS_UDP_ST_FLAG_IPV4) {
		skb_push(skb, sizeof(*iph));
		skb_reset_network_header(skb);
		iph = ip_hdr(skb);
		nss_udp_st_generate_ipv4_hdr(iph, ip_len, rules);
		data = skb_put(skb, pkt_sz - sizeof(*iph) - sizeof(*uh));
		memset(data, 0, pkt_sz - sizeof(*iph) - sizeof(*uh));
	} else if (rules->flags & NSS_UDP_ST_FLAG_IPV6) {
		skb_push(skb, sizeof(*ipv6h));
		skb_reset_network_header(skb);
		ipv6h = ipv6_hdr(skb);
		nss_udp_st_generate_ipv6_hdr(ipv6h, ip_len, rules);
		data = skb_put(skb, pkt_sz - sizeof(*ipv6h) - sizeof(*uh));
		memset(data, 0, pkt_sz - sizeof(*ipv6h) - sizeof(*uh));
	} else {
		atomic_long_inc(&nust.stats.errors[NSS_UDP_ST_ERROR_INCORRECT_IP_VERSION]);
		kfree_skb(skb);
		return;
	}

	switch (ndev->type) {
	case ARPHRD_PPP:
		if (rules->flags & NSS_UDP_ST_FLAG_IPV4) {
			ppp_protocol = PPP_IP;
		} else {
			ppp_protocol = PPP_IPV6;
		}

		nss_udp_st_generate_pppoe_hdr(skb, ppp_protocol);

		if(is_vlan_dev(info.dev)) {
			nss_udp_st_generate_vlan_hdr(skb, info.dev);
		}

		/*
		 * populate ethernet header
		 */
		nss_udp_st_generate_eth_hdr(skb, xmit_dev->dev_addr, info.pa.remote);
		break;

	case ARPHRD_ETHER:
		if (rules->flags & NSS_UDP_ST_FLAG_IPV4) {
			skb->protocol = htons(ETH_P_IP);
		} else {
			skb->protocol = htons(ETH_P_IPV6);
		}

		if(is_vlan_dev(ndev)) {
			nss_udp_st_generate_vlan_hdr(skb, ndev);
		}

		/*
		 * populate ethernet header
		 */
		nss_udp_st_generate_eth_hdr(skb, xmit_dev->dev_addr, rules->dst_mac);
		break;

	default:
		break;
	}

	/*
	 * tx packet
	 */
	skb->dev = xmit_dev;
	if (xmit_dev->netdev_ops->ndo_start_xmit(skb, xmit_dev) != NETDEV_TX_OK) {
		kfree_skb(skb);
		atomic_long_inc(&nust.stats.errors[NSS_UDP_ST_ERROR_PACKET_DROP]);
		return;
	}

	nss_udp_st_update_stats(ip_len + sizeof(struct ethhdr));
}

/*
 * nss_udp_st_set_dev()
 *	get net_device
 */
static bool nss_udp_st_set_dev(void)
{
	nust_dev = dev_get_by_name(&init_net, nust.config.net_dev);
	if (!nust_dev) {
		pr_err("Cannot find the net device\n");
		return false;
	}
	return true;
}

/*
 * nss_udp_st_tx_valid()
 *	check if test time has elapsed
 */
bool nss_udp_st_tx_valid(void)
{
	long long elapsed = atomic_long_read(&nust.stats.timer_stats[NSS_UDP_ST_STATS_TIME_ELAPSED]);

	if (elapsed < (nust.time * 1000)) {
		return true;
	}
	nust.mode = NSS_UDP_ST_STOP;
	return false;
}

/*
 * nss_udp_st_vlan_iface_config
 *      Configure the WLAN interface as VLAN
 */
static int nss_udp_st_vlan_iface_config(struct net_device *dev)
{
        xmit_dev = vlan_dev_next_dev(dev);
        if (!xmit_dev) {
                pr_err("Cannot find the physical net device\n");
                return -1;
        }

        if (is_vlan_dev(xmit_dev) || xmit_dev->type != ARPHRD_ETHER) {
                pr_warn("%px: QinQ or non-ethernet VLAN master (%s) is not supported\n", dev,
                                xmit_dev->name);
                return -1;
        }

        vh.h_vlan_TCI = vlan_dev_vlan_id(dev);
        vh.h_vlan_encapsulated_proto = ntohs(vlan_dev_vlan_proto(dev));

        return 0;
}

/*
 * nss_udp_st_pppoe_iface_config
 *	Configure the WLAN interface as PPPoE
 */
static int nss_udp_st_pppoe_iface_config(struct net_device *dev)
{
	struct ppp_channel *ppp_chan[1];
	int channel_count;
	int channel_protocol;
	int ret = 0;

	/*
	 * Gets the PPPoE channel information.
	 */
	channel_count = ppp_hold_channels(dev, ppp_chan, 1);
	if (channel_count != 1) {
		pr_warn("%px: Unable to get the channel for device: %s\n", dev, dev->name);
		return -1;
	}

	channel_protocol = ppp_channel_get_protocol(ppp_chan[0]);
	if (channel_protocol != PX_PROTO_OE) {
		pr_warn("%px: PPP channel protocol is not PPPoE for device: %s\n", dev, dev->name);
		ppp_release_channels(ppp_chan, 1);
		return -1;
	}

	if (pppoe_channel_addressing_get(ppp_chan[0], &info)) {
		pr_warn("%px: Unable to get the PPPoE session information for device: %s\n", dev, dev->name);
		ppp_release_channels(ppp_chan, 1);
		return -1;
	}

	/*
	 * Check if the next device is a VLAN (eth0-eth0.100-pppoe-wan)
	 */
	if (is_vlan_dev(info.dev)) {
		/*
		 * Next device is a VLAN device (eth0.100)
		 */
		if (nss_udp_st_vlan_iface_config(info.dev) < 0) {
			pr_warn("%px: Unable to get PPPoE's VLAN device's (%s) next dev\n", dev,
 info.dev->name);
			ret = -1;
			goto fail;
		}
	} else {
		/*
		 * PPPoE interface can be created on linux bridge, OVS bridge and LAG devices.
		 * udp_st doesn't support these hierarchies.
		 */
		if ((info.dev->priv_flags & (IFF_EBRIDGE | IFF_OPENVSWITCH))
			|| ((info.dev->flags & IFF_MASTER) && (info.dev->priv_flags & IFF_BONDING))) {
			pr_warn("%px: PPPoE over bridge and LAG interfaces are not supported, dev: %s info.dev: %s\n",dev, dev->name, info.dev->name);
			ret = -1;
			goto fail;

		}

		/*
		 * PPPoE only (eth0-pppoe-wan)
		 */
		xmit_dev = info.dev;
	}

fail:
	dev_put(info.dev);
	ppp_release_channels(ppp_chan, 1);
	return ret;
}

/*
 * nss_udp_st_tx_work_send_packets()
 *	generate and send packets per rule
 */
static void nss_udp_st_tx_work_send_packets(void)
{
	int i = 0;
	struct nss_udp_st_rules *pos = NULL;
	struct nss_udp_st_rules *n = NULL;

	if (!nss_udp_st_tx_valid()  || nust.mode == NSS_UDP_ST_STOP ) {
		dev_put(nust_dev);
		tx_hr_restart = HRTIMER_NORESTART;
		return;
	}

	list_for_each_entry_safe(pos, n, &nust.rules.list, list) {
		for (i = 0; i < nss_udp_st_tx_num_pkt; i++) {
			/*
			 * check if test time has elapsed or test has been stopped
			 */
			if (!nss_udp_st_tx_valid()  || nust.mode == NSS_UDP_ST_STOP ) {
				dev_put(nust_dev);
				tx_hr_restart = HRTIMER_NORESTART;
				return;
			}

			nss_udp_st_tx_packets(nust_dev, pos);
		}
	}
	tx_hr_restart = HRTIMER_RESTART;
}

/*
 * nss_udp_st_tx_init()
 *	initialize speedtest for tx
 */
static bool nss_udp_st_tx_init(void)
{
	uint64_t total_bps;

	if (nust.config.rate > NSS_UDP_ST_RATE_MAX) {
		atomic_long_inc(&nust.stats.errors[NSS_UDP_ST_ERROR_INCORRECT_RATE]);
		return false;
	}

	if (nust.config.buffer_sz > NSS_UDP_ST_BUFFER_SIZE_MAX) {
		atomic_long_inc(&nust.stats.errors[NSS_UDP_ST_ERROR_INCORRECT_BUFFER_SIZE]);
		return false;
	}
	total_bps = (uint64_t)nust.config.rate * 1024 * 1024;

	/*
	 * calculate number of pkts to send per rule per 10 ms
	 */
	nss_udp_st_tx_num_pkt = total_bps / (nust.rule_count * (nust.config.buffer_sz + sizeof(struct ethhdr)) * 8 * NSS_UDP_ST_TX_TIMER);
	nss_udp_st_tx_num_pkt ++;
	pr_debug("total number of packets to tx every 100ms %llu\n",nss_udp_st_tx_num_pkt);
	if(!nss_udp_st_set_dev()) {
		return false;
	}

	return true;
}

/*
 * nss_udp_st_hrtimer_cleanup()
 *	cancel hrtimer
 */
void nss_udp_st_hrtimer_cleanup(void)
{
	hrtimer_cancel(&tx_hr_timer);
	tx_hr_restart = HRTIMER_NORESTART;
}

/*
 * nss_udp_st_hrtimer_callback()
 *	hrtimer callback function
 */
static enum hrtimer_restart nss_udp_st_hrtimer_callback(struct hrtimer *timer)
{
	nss_udp_st_tx_work_send_packets();
	if(tx_hr_restart == HRTIMER_RESTART) {
		hrtimer_forward_now(timer, kt);
	}
	return tx_hr_restart;
}

/*
 * nss_udp_st_hrtimer_init()
 *	initialize hrtimer
 */
void nss_udp_st_hrtimer_init(void)
{
	tx_hr_restart = HRTIMER_RESTART;
	kt = ktime_set(0,10000000);
	hrtimer_init(&tx_hr_timer, CLOCK_REALTIME, HRTIMER_MODE_ABS_HARD);
	tx_hr_timer.function = &nss_udp_st_hrtimer_callback;
}

/*
 * nss_udp_st_tx()
 *	start speedtest for tx
 */
bool nss_udp_st_tx(void)
{
	if (!nss_udp_st_tx_init()) {
		return false;
	}

	switch (nust_dev->type) {
	case ARPHRD_PPP:
		if(nss_udp_st_pppoe_iface_config(nust_dev) < 0) {
			pr_err("Could not configure pppoe, dev: %s\n", nust_dev->name);
			return false;
		}
		break;

	case ARPHRD_ETHER:
		if ((nust_dev->priv_flags & (IFF_EBRIDGE | IFF_OPENVSWITCH))
			|| ((nust_dev->flags & IFF_MASTER) && (nust_dev->priv_flags & IFF_BONDING))) {
			pr_err("Bridge and LAG interfaces are not supported, dev: %s\n", nust_dev->name);
			return false;
		}

                if (is_vlan_dev(nust_dev)) {
                        if (nss_udp_st_vlan_iface_config(nust_dev) < 0) {
                                pr_err("Could not configure vlan, dev: %s\n", nust_dev->name);
                                return false;
                        }
                } else {
			xmit_dev = nust_dev;
		}

                break;

        default:
                pr_err("Unsupported speedtest interface: %s\n", nust_dev->name);
		return false;
        }

	pr_debug("Speedtest interface: %s\n", nust_dev->name);

	if (!tx_timer_flag) {
		nss_udp_st_hrtimer_init();
		hrtimer_start(&tx_hr_timer, kt, HRTIMER_MODE_ABS_HARD);
		tx_timer_flag = 1;
	} else {
		hrtimer_restart(&tx_hr_timer);
	}

	return true;
}
