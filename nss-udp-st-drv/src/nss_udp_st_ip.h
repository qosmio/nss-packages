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
#ifndef __NSS_UDP_ST_IP_H
#define __NSS_UDP_ST_IP_H

/*
 *  Converts the format of an IPv6 address from NSS to Linux
 */
#define NSS_UDP_ST_IPV6_ADDR_TO_IN6_ADDR(in6, ipv6) \
	{ \
		in6.in6_u.u6_addr32[0] = ((uint32_t *)ipv6)[0]; \
		in6.in6_u.u6_addr32[1] = ((uint32_t *)ipv6)[1]; \
		in6.in6_u.u6_addr32[2] = ((uint32_t *)ipv6)[2]; \
		in6.in6_u.u6_addr32[3] = ((uint32_t *)ipv6)[3]; \
	}

int nss_udp_st_get_ipaddr_ntoh(const char *arg, uint16_t data_sz, uint32_t *data);

void nss_udp_st_get_ipv6_addr_hton(uint32_t src[4], uint32_t dst[4]);

void nss_udp_st_get_ipv6_addr_ntoh(uint32_t src[4], uint32_t dst[4]);

int nss_udp_st_get_macaddr_ipv4(uint32_t ip_addr, uint8_t mac_addr[]);

int nss_udp_st_get_macaddr_ipv6(uint32_t ip_addr[4], uint8_t mac_addr[]);

bool nss_udp_st_compare_ipv6(uint32_t src[4], uint32_t dst[4]);

/*
 * nss_udp_st_swap_addr_ipv6()
 *  Swap the ipv6 source and destination address.
 */
static inline void nss_udp_st_swap_addr_ipv6(uint32_t *src, uint32_t *dst)
{
	uint32_t temp[4];

	if (src == dst) {
		memcpy(temp, src, sizeof(temp));
		src = temp;
	}

	dst[0] = src[3];
	dst[1] = src[2];
	dst[2] = src[1];
	dst[3] = src[0];
}

#endif /*NSS_UDP_ST_IP_H*/
