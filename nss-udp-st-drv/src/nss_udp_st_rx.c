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
#include <linux/list.h>
#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack_core.h>
#include "nss_udp_st_public.h"

/*
 * nss_udp_st_rx_ipv4_pre_routing_hook()
 *	pre-routing hook into netfilter packet monitoring point for IPv4
 */
unsigned int nss_udp_st_rx_ipv4_pre_routing_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct udphdr *uh;
	struct iphdr *iph;
	struct nss_udp_st_rules *rules = NULL;
	struct nss_udp_st_rules *n = NULL;

	iph = (struct iphdr *)skb_network_header(skb);

	/*
	 * Not a UDP speedtest packet
	 */
	if (iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}

	uh = (struct udphdr *)skb_transport_header(skb);

	list_for_each_entry_safe(rules, n, &nust.rules.list, list) {
		/*
		 * If incoming packet matches 5tuple, it is a speedtest packet.
		 * Increase Rx packet stats and drop packet.
		 */
		if ((rules->flags & NSS_UDP_ST_FLAG_IPV4) &&
			(rules->sip.ip.ipv4 == ntohl(iph->daddr)) &&
			(rules->dip.ip.ipv4 == ntohl(iph->saddr)) &&
			(rules->sport == ntohs(uh->source)) &&
			(rules->dport == ntohs(uh->dest)) ) {
				nss_udp_st_update_stats(ntohs(iph->tot_len) + sizeof(struct ethhdr));
				kfree_skb(skb);
				return NF_STOLEN;
		}
	}
	return NF_ACCEPT;
}

/*
 * nss_udp_st_rx_ipv6_pre_routing_hook()
 *	pre-routing hook into netfilter packet monitoring point for IPv6
 */
unsigned int nss_udp_st_rx_ipv6_pre_routing_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct udphdr *uh;
	struct ipv6hdr *iph;
	struct in6_addr saddr;
	struct in6_addr daddr;
	struct nss_udp_st_rules *rules = NULL;
	struct nss_udp_st_rules *n = NULL;

	iph = (struct ipv6hdr *)skb_network_header(skb);

	/*
	 * Not a UDP speedtest packet
	 */
	if (iph->nexthdr != IPPROTO_UDP) {
		return NF_ACCEPT;
	}

	uh = (struct udphdr *)skb_transport_header(skb);

	nss_udp_st_get_ipv6_addr_ntoh(iph->saddr.s6_addr32, saddr.s6_addr32);
	nss_udp_st_get_ipv6_addr_ntoh(iph->daddr.s6_addr32, daddr.s6_addr32);

	list_for_each_entry_safe(rules, n, &nust.rules.list, list) {

		/*
		 * If incoming packet matches 5tuple, it is a speedtest packet.
		 * Increase Rx packet stats and drop packet.
		 */
		if ((rules->flags & NSS_UDP_ST_FLAG_IPV6) &&
			(nss_udp_st_compare_ipv6(rules->sip.ip.ipv6, daddr.s6_addr32)) &&
			(nss_udp_st_compare_ipv6(rules->dip.ip.ipv6, saddr.s6_addr32)) &&
			(rules->sport == ntohs(uh->source)) &&
			(rules->dport == ntohs(uh->dest))) {
				nss_udp_st_update_stats(ntohs(iph->payload_len) + sizeof(struct ethhdr));
				kfree_skb(skb);
				return NF_STOLEN;
		}
	}
	return NF_ACCEPT;
}
