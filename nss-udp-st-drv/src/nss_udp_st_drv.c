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

#include <net/act_api.h>
#include <linux/major.h>
#include <net/netfilter/nf_conntrack_core.h>
#include "nss_udp_st_public.h"

#define DEVICE_NAME "nss_udp_st"
#define CLASS_NAME "nss_udp_st"

static const struct file_operations nss_udp_st_ops;
static struct class *dump_class;
static int dump_major;

struct nss_udp_st nust;
struct delayed_work nss_udp_st_tx_delayed_work;
struct workqueue_struct *work_queue;
void nss_udp_st_update_stats(size_t pkt_size);
uint64_t nss_udp_st_tx_num_pkt;
struct net_device *nust_dev;

/*
 * nss_udp_st_rx_ipv4_pre_routing_hook
 *	pre-routing hook into netfilter packet monitoring point for IPv4
 */
static struct nf_hook_ops nss_udp_st_nf_ipv4_ops[] __read_mostly = {
	{
		.hook   =   nss_udp_st_rx_ipv4_pre_routing_hook,
		.pf =   NFPROTO_IPV4,
		.hooknum    =   NF_INET_PRE_ROUTING,
		.priority   =   NF_IP_PRI_RAW_BEFORE_DEFRAG,
	},
};

/*
 * nss_udp_st_rx_ipv6_pre_routing_hook
 *	pre-routing hook into netfilter packet monitoring point for IPv6
 */
static struct nf_hook_ops nss_udp_st_nf_ipv6_ops[] __read_mostly = {
	{
		.hook	=	nss_udp_st_rx_ipv6_pre_routing_hook,
		.pf	=	NFPROTO_IPV6,
		.hooknum	=	NF_INET_PRE_ROUTING,
		.priority	=	NF_IP_PRI_RAW_BEFORE_DEFRAG,
	},
};

/*
 * nss_udp_st_check_rules()
 *	check for ARP resolution and valid return mac
 */
static int nss_udp_st_check_rules(struct nss_udp_st_rules *rules)
{
	if (rules->flags == NSS_UDP_ST_FLAG_IPV4) {
		if (nss_udp_st_get_macaddr_ipv4(rules->dip.ip.ipv4, (uint8_t *)&rules->dst_mac)) {
			pr_err("Error in Updating the Return MAC Address\n");
			return -EINVAL;
		}
	} else if (rules->flags == NSS_UDP_ST_FLAG_IPV6) {
		if (nss_udp_st_get_macaddr_ipv6(rules->dip.ip.ipv6, (uint8_t *)&rules->dst_mac)) {
			pr_err("Error in Updating the Return MAC Address\n");
			return -EINVAL;
		}
	} else {
		pr_err("invalid ip version flag\n");
		return -EINVAL;
	}
	return 0;
}

/*
 * nss_udp_st_clear_rules()
 *	clear rules list
 */
static void nss_udp_st_clear_rules(void)
{
	struct nss_udp_st_rules *pos = NULL;
	struct nss_udp_st_rules *n = NULL;

	list_for_each_entry_safe(pos, n, &nust.rules.list, list) {
		list_del(&pos->list);
		kfree(pos);
	}
	nust.rule_count = 0;
}

/*
 * nss_udp_st_open()
 *	open for file ops on /dev/nss-udp-st
 */
static int nss_udp_st_open(struct inode *inode, struct file *file)
{
	return 0;
}

/*
 * nss_udp_st_release()
 *	release /dev/nss-udp-st
 */
static int nss_udp_st_release(struct inode *inode, struct file *file)
{
	return 0;
}

/*
 * nss_udp_st_read()
 *	send stats to userspace
 */
static ssize_t nss_udp_st_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	int copied = 0;
	copied = copy_to_user(buf, &nust.stats, sizeof(struct nss_udp_st_stats));
	return copied;
}

/*
 * nss_udp_st_write()
 *	receive rules from userspace
 */
static ssize_t nss_udp_st_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	int ret = 0;
	struct nss_udp_st_opt opt;
	struct nss_udp_st_rules *rules;

	/*
	 * don't push rules if test has already started
	 */
	if (nust.mode == NSS_UDP_ST_START) {
		pr_err("Test already started\n");
		return -EINVAL;
	}

	rules = (struct nss_udp_st_rules *)kzalloc(sizeof(struct nss_udp_st_rules), GFP_KERNEL);
	if (!rules) {
		atomic_long_inc(&nust.stats.errors[NSS_UDP_ST_ERROR_MEMORY_FAILURE]);
		return -EINVAL;
	}

	ret = copy_from_user((void *)(uintptr_t)&opt, (void __user *)buf, sizeof(struct nss_udp_st_opt));
	if (ret) {
		kfree(rules);
		return -EINVAL;
	}
	rules->sport = opt.sport;
	rules->dport = opt.dport;
	if(opt.ip_version == 4) {
		rules->flags |= NSS_UDP_ST_FLAG_IPV4;
		nss_udp_st_get_ipaddr_ntoh(opt.sip, sizeof(struct in_addr), &rules->sip.ip.ipv4);
		nss_udp_st_get_ipaddr_ntoh(opt.dip, sizeof(struct in_addr), &rules->dip.ip.ipv4);
	} else if(opt.ip_version == 6) {
		rules->flags |= NSS_UDP_ST_FLAG_IPV6;
		nss_udp_st_get_ipaddr_ntoh(opt.sip, sizeof(struct in6_addr), rules->sip.ip.ipv6);
		nss_udp_st_get_ipaddr_ntoh(opt.dip, sizeof(struct in6_addr), rules->dip.ip.ipv6);
	} else {
		kfree(rules);
		return -EINVAL;
	}

	ret = nss_udp_st_check_rules(rules);
	if (ret) {
		kfree(rules);
		return -EINVAL;
	}

	list_add_tail(&(rules->list), &(nust.rules.list));
	nust.rule_count++;
	return 0;
}

/*
 * nss_udp_st_reset_stats()
 *	clear stats before starting test
 */
static void nss_udp_st_reset_stats(void) {
	memset(&nust.stats, 0, sizeof(struct nss_udp_st_stats));
	nust.stats.first_pkt = true;
	nss_udp_st_tx_num_pkt = 0;
}

/*
 * nss_udp_st_ioctl()
 *	receive ioctl to init / start / stop test
 */
static long nss_udp_st_ioctl(struct file *file, unsigned int ioctl_num,
				unsigned long arg)
{
	int ret = 0;

	switch (ioctl_num) {
	case NSS_UDP_ST_IOCTL_INIT:
		memset(&(nust.config), 0, sizeof(struct nss_udp_st_param));
		ret = copy_from_user((void *)&(nust.config), (void __user *)arg, sizeof(struct nss_udp_st_param));
		if (ret) {
			return -EINVAL;
		}
		break;

	case NSS_UDP_ST_IOCTL_START_TX:
		if (nust.mode == NSS_UDP_ST_START) {
			pr_err("Tx test already started\n");
			return -EINVAL;
		}

		nss_udp_st_reset_stats();
		nust.dir = NSS_UDP_ST_TX;

		ret = copy_from_user((void *)&(nust.time), (void __user *)arg, sizeof(nust.time));
		if (ret) {
			return -EINVAL;
		}
		if (!nust.time) {
			nust.time = NSS_UDP_ST_TX_DEFAULT_TIMEOUT;
		}
		if (!nss_udp_st_tx()) {
			pr_err("Unable to start Tx test\n");
			return -EINVAL;
		}
		nust.mode = NSS_UDP_ST_START;
		break;

	case NSS_UDP_ST_IOCTL_START_RX:
		if (nust.mode == NSS_UDP_ST_START) {
			pr_err("Rx test already started\n");
			return -EINVAL;
		}

		nss_udp_st_reset_stats();
		nust.dir = NSS_UDP_ST_RX;

		/*
		 * register pre-routing hook for rx path
		 */
		ret = nf_register_net_hooks(&init_net, nss_udp_st_nf_ipv4_ops, ARRAY_SIZE(nss_udp_st_nf_ipv4_ops));
		if (ret < 0) {
			pr_err("Can't register Rx netfilter hooks.\n");
			return -EINVAL;
		}

		ret = nf_register_net_hooks(&init_net, nss_udp_st_nf_ipv6_ops, ARRAY_SIZE(nss_udp_st_nf_ipv6_ops));
		if (ret < 0) {
			pr_err("Can't register Rx netfilter hooks.\n");
			nf_unregister_net_hooks(&init_net, nss_udp_st_nf_ipv4_ops, ARRAY_SIZE(nss_udp_st_nf_ipv4_ops));
			return -EINVAL;
		}
		nust.mode = NSS_UDP_ST_START;
		break;

	case NSS_UDP_ST_IOCTL_STOP:
		if (nust.mode == NSS_UDP_ST_STOP)
			break;

		nust.mode = NSS_UDP_ST_STOP;

		if (nust.dir == NSS_UDP_ST_RX) {
			/*
			 * de-register pre-routing hook for rx path
			 */
			nf_unregister_net_hooks(&init_net, nss_udp_st_nf_ipv4_ops, ARRAY_SIZE(nss_udp_st_nf_ipv4_ops));
			nf_unregister_net_hooks(&init_net, nss_udp_st_nf_ipv6_ops, ARRAY_SIZE(nss_udp_st_nf_ipv6_ops));
		} else {
			nss_udp_st_hrtimer_cleanup();
		}
		nss_udp_st_clear_rules();
		break;

	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

/*
 * file ops for /dev/nss_udp_st
 */
static const struct file_operations nss_udp_st_ops = {
	.open       =   nss_udp_st_open,
	.read       =   nss_udp_st_read,
	.write      =  nss_udp_st_write,
	.unlocked_ioctl = nss_udp_st_ioctl,
	.release    =   nss_udp_st_release,
};

/*
 * nss_udp_st_init()
 *	create char device /dev/nss_udp_st
 */
static int __init nss_udp_st_init(void)
{
	int ret = 0;
	struct device *dump_dev;

	memset(&nust, 0, sizeof(struct nss_udp_st));
	INIT_LIST_HEAD(&(nust.rules.list));

	dump_major = register_chrdev(UNNAMED_MAJOR, DEVICE_NAME, &nss_udp_st_ops);
	if (dump_major < 0) {
		ret = dump_major;
		pr_err("Unable to allocate a major number err = %d\n", ret);
		goto reg_failed;
	}

	dump_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(dump_class)) {
		ret = PTR_ERR(dump_class);
		pr_err("Unable to create dump class = %d\n", ret);
		goto class_failed;
	}

	dump_dev = device_create(dump_class, NULL, MKDEV(dump_major, 0), NULL, DEVICE_NAME);
	if (IS_ERR(dump_dev)) {
		ret = PTR_ERR(dump_dev);
		pr_err("Unable to create a device err = %d\n", ret);
		goto device_failed;
	}
	return ret;

device_failed:
	class_destroy(dump_class);
class_failed:
	unregister_chrdev(dump_major, DEVICE_NAME);
reg_failed:
	return ret;
}

/*
 * nss_udp_st_exit()
 *	clean up for /dev/nss_udp_st
 */
static void __exit nss_udp_st_exit(void)
{
	nust.mode = NSS_UDP_ST_STOP;
	device_destroy(dump_class, MKDEV(dump_major, 0));
	class_destroy(dump_class);
	unregister_chrdev(dump_major, DEVICE_NAME);
}

/*
 * nss_udp_st_update_stats()
 *  update packet and time stats for tx/rx
 */
void nss_udp_st_update_stats(size_t pkt_size)
{
	long time_curr;
	long time_start;

	if (nust.stats.first_pkt) {
		atomic_long_set(&nust.stats.timer_stats[NSS_UDP_ST_STATS_TIME_START], (jiffies * 1000/HZ));
		nust.stats.first_pkt = false;
	}

	if (nust.dir == NSS_UDP_ST_TX) {
		atomic_long_inc(&nust.stats.p_stats.tx_packets);
		atomic_long_add(pkt_size, &nust.stats.p_stats.tx_bytes);
	}

	if (nust.dir == NSS_UDP_ST_RX) {
		atomic_long_inc(&nust.stats.p_stats.rx_packets);
		atomic_long_add(pkt_size, &nust.stats.p_stats.rx_bytes);
	}

	atomic_long_set(&nust.stats.timer_stats[NSS_UDP_ST_STATS_TIME_CURRENT], (jiffies * 1000/HZ));

	time_curr = atomic_long_read(&nust.stats.timer_stats[NSS_UDP_ST_STATS_TIME_CURRENT]);
	time_start = atomic_long_read(&nust.stats.timer_stats[NSS_UDP_ST_STATS_TIME_START]);
	atomic_long_set(&nust.stats.timer_stats[NSS_UDP_ST_STATS_TIME_ELAPSED], (long)(time_curr - time_start));
}

module_init(nss_udp_st_init);
module_exit(nss_udp_st_exit);

MODULE_AUTHOR("Qualcomm Technologies");
MODULE_DESCRIPTION("NSS UDP Speedtest");
MODULE_LICENSE("Dual BSD/GPL");
