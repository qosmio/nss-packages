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

#include <linux/inet.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/etherdevice.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/dst.h>
#include <net/ipv6.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include "nss_udp_st_ip.h"

#define NSS_UDP_ST_IPV4_SIZE	sizeof(struct in_addr)
#define NSS_UDP_ST_IPV6_SIZE	sizeof(struct in6_addr)

/*
 * nss_udp_st_get_ipaddr_ntoh()
 *	extract the IPv4 or IPv6 address in host order from the incoming data
 */
int nss_udp_st_get_ipaddr_ntoh(const char *arg, uint16_t data_sz, uint32_t *data)
{

	uint32_t dest[4];

	if (!arg || !data) {
		return -EINVAL;
	}

	switch(data_sz) {
	case NSS_UDP_ST_IPV4_SIZE: /* IPv4 */
		if(!in4_pton(arg, -1, (uint8_t *)data, '\0', NULL)) {
			return -EINVAL;
		}

		data[0] = ntohl(data[0]);
		return 0;

	case NSS_UDP_ST_IPV6_SIZE: /* IPv6 */
		if(!in6_pton(arg, -1,(uint8_t *)data, -1, NULL)) {
			return -EINVAL;
		}

		nss_udp_st_swap_addr_ipv6(data, dest);

		data[0] = ntohl(dest[0]);
		data[1] = ntohl(dest[1]);
		data[2] = ntohl(dest[2]);
		data[3] = ntohl(dest[3]);

		return 0;

	default:
		pr_err("IP address storage incorrect:%d\n", data_sz);
		return -E2BIG;
    }
}

/*
 * nss_udp_st_get_neigh_ipv4()
 *	Returns neighbour reference for a given IP address
 */
static struct neighbour *nss_udp_st_get_neigh_ipv4(uint32_t ip_addr)
{
	struct neighbour *neigh;
	struct rtable *rt;
	struct dst_entry *dst;

	/*
	 * search for route entry
	 */
	rt = ip_route_output(&init_net, ip_addr, 0, 0, 0);
	if (IS_ERR(rt)) {
		return NULL;
	}

	dst = (struct dst_entry *)rt;

	/*
	 * neighbour lookup using IP address in the route table
	 */
	neigh = dst_neigh_lookup(dst, &ip_addr);
	if (likely(neigh)) {
		dst_release(dst);
		return neigh;
	}

	/*
	 * neighbour lookup using IP address, device in the arp table
	 */
	neigh = neigh_lookup(&arp_tbl, &ip_addr, dst->dev);
	if (likely(neigh)) {
		dst_release(dst);
		return neigh;
	}

	/*
	 * dst reference count was held during the lookup
	 */
	dst_release(dst);
	return NULL;
}

/*
 * nss_udp_st_get_macaddr_get_ipv4()
 *	Return the hardware (MAC) address of the given IPv4 address, if any.
 *
 * Returns 0 on success or a negative result on failure.
 * We look up the rtable entry for the address and,
 * from its neighbour structure,obtain the hardware address.
 * This means we will also work if the neighbours are routers too.
 */
int nss_udp_st_get_macaddr_ipv4(uint32_t ip_addr, uint8_t mac_addr[])
{
	struct neighbour *neigh;

	/*
	 * handle multicast IP address seperately
	 */
	if (ipv4_is_multicast(htonl(ip_addr))) {
		return -EINVAL;
	}

	/*
	 * retrieve the neighbour
	 */
	rcu_read_lock();
	neigh = nss_udp_st_get_neigh_ipv4(htonl(ip_addr));
	if (!neigh) {
		rcu_read_unlock();
		pr_err("neighbour lookup failed for IP:0x%x\n", ip_addr);
		return -ENODEV;
	}
	rcu_read_unlock();

	if ((neigh->nud_state & NUD_VALID) == 0) {
		pr_err("neighbour state is invalid for IP:0x%x\n", ip_addr);
		goto fail;
	}

	if (!neigh->dev) {
		pr_err("neighbour device not found for IP:0x%x\n", ip_addr);
		goto fail;
	}

	if (is_multicast_ether_addr(neigh->ha)) {
		pr_err( "neighbour MAC address is multicast or broadcast\n");
		goto fail;
	}

	ether_addr_copy(mac_addr, neigh->ha);
	neigh_release(neigh);
	return 0;

fail:
	neigh_release(neigh);
	return -ENODEV;
}

/*
 * nss_udp_st_get_neigh_ipv6()
 *	Returns neighbour reference for a given IP address
 */
struct neighbour *nss_udp_st_get_neigh_ipv6(uint32_t dst_addr[4])
{
	struct neighbour *neigh;
	struct dst_entry *dst;
	struct rt6_info *rt;
	struct in6_addr daddr;

	NSS_UDP_ST_IPV6_ADDR_TO_IN6_ADDR(daddr, dst_addr);

	rt = rt6_lookup(&init_net, &daddr, NULL, 0, NULL, 0);
	if (!rt) {
		return NULL;
	}

	dst = (struct dst_entry *)rt;

	/*
	 * neighbour lookup using IP address in the route table
	 */
	neigh = dst_neigh_lookup(dst, &daddr);
	if (likely(neigh)) {
		neigh_hold(neigh);
		dst_release(dst);
		return neigh;
	}
	dst_release(dst);

	return NULL;
}

/*
 * nss_udp_st_get_ipv6_addr_hton()
 *	Convert the ipv6 address from host order to network order.
 */
void nss_udp_st_get_ipv6_addr_hton(uint32_t src[4], uint32_t dst[4])
{
	nss_udp_st_swap_addr_ipv6(src, dst);

	dst[0] = htonl(dst[0]);
	dst[1] = htonl(dst[1]);
	dst[2] = htonl(dst[2]);
	dst[3] = htonl(dst[3]);
}

/*
 * nss_udp_st_get_addr_ntoh()
 *	Convert the ipv6 address from network order to host order.
 */
void nss_udp_st_get_ipv6_addr_ntoh(uint32_t src[4], uint32_t dst[4])
{
	nss_udp_st_swap_addr_ipv6(src, dst);

	dst[0] = ntohl(dst[0]);
	dst[1] = ntohl(dst[1]);
	dst[2] = ntohl(dst[2]);
	dst[3] = ntohl(dst[3]);
}

/*
 * nss_udp_st_get_macaddr_get_ipv6()
 *	Return the hardware (MAC) address of the given ipv6 address, if any.
 *
 * Returns 0 on success or a negative result on failure.
 * We look up the rtable entry for the address and,
 * from its neighbour structure,obtain the hardware address.
 * This means we will also work if the neighbours are routers too.
 */
int nss_udp_st_get_macaddr_ipv6(uint32_t ip_addr[4], uint8_t mac_addr[])
{
	struct neighbour *neigh;
	struct  in6_addr addr;

	nss_udp_st_get_ipv6_addr_hton(ip_addr, addr.s6_addr32);

	if (ipv6_addr_is_multicast(&addr)) {
		return 0;
	}

	/*
	 * retrieve the neighbour
	 */
	rcu_read_lock();
	neigh = nss_udp_st_get_neigh_ipv6(addr.s6_addr32);
	if (!neigh) {
		rcu_read_unlock();
		pr_info("neighbour lookup failed for %pI6c\n", addr.s6_addr32);
		return -ENODEV;
	}
	rcu_read_unlock();

	if ((neigh->nud_state & NUD_VALID) == 0) {
		pr_err("neighbour state is invalid for %pI6c\n", addr.s6_addr32);
		goto fail;
	}

	if (!neigh->dev) {
		pr_err("neighbour device not found for %pI6c\n", addr.s6_addr32);
		goto fail;
	}

	if (is_multicast_ether_addr(neigh->ha)) {
		pr_err("neighbour MAC address is multicast or broadcast\n");
		goto fail;
	}

	ether_addr_copy(mac_addr, neigh->ha);
	neigh_release(neigh);
	return 0;
fail:
	neigh_release(neigh);
	return -ENODEV;
}

/*
 * nss_udp_st_compare_ipv6()
 *	Comapre ipv6 source and dest addresses
 */
bool nss_udp_st_compare_ipv6(uint32_t src[4], uint32_t dst[4])
{
	if ((src[0] == dst[0]) && (src[1] == dst[1]) &&
		(src[2] == dst[2]) && (src[3]==dst[3])) {
		return true;
	}

	return false;
}
