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

/*
 * @file NSS UDP Speetest App
 */

#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include "nss-udp-st.h"

struct nss_udp_st_param st_param;
struct nss_udp_st_opt st_opt;
struct nss_udp_st_cfg st_cfg;
struct nss_udp_st_stat st_stat;

struct option long_options[] =
{
	{"mode", required_argument, NULL, 'm'},
	{"type", required_argument, NULL, 'x'},
	{"sip", required_argument, NULL, 's'},
	{"dip", required_argument, NULL, 'd'},
	{"sport", required_argument, NULL, 'y'},
	{"dport", required_argument, NULL, 'z'},
	{"net_dev", required_argument, NULL, 'n'},
	{"version", required_argument, NULL, 'f'},
	{"time", required_argument, NULL, 't'},
	{"rate", required_argument, NULL, 'r'},
	{"buffer_sz", required_argument, NULL, 'b'},
	{"dscp", required_argument, NULL, 'c'},
	{"help", no_argument, NULL, 'h'},
	{0, 0, 0, 0}
};

/*
 * nss_udp_st_init()
 *	Load nss speedtest driver and initialize test parameters
 */
static int nss_udp_st_init(void)
{
	int ret = 0;

	mkdir(NSS_UDP_ST_LOG, 0777);
	ret = ioctl(st_cfg.handle, NSS_UDP_ST_IOCTL_INIT, &st_param);
	if (ret < 0) {
		printf("ioctl error %d\n", ret);
		return -EINVAL;
	}

	return 0;
}

/*
 * nss_udp_st_final()
 *	Unload nss speedtest driver
 */
static void nss_udp_st_final(void)
{
	system("rmmod nss-udp-st.ko");
}

/*
 * nss_udp_st_create()
 *	Configure NSS UDP speedtest rules
 */
static int nss_udp_st_create(void)
{
	FILE *fp = NULL;

	fp = fopen(NSS_UDP_ST_RULES, "a+");
	if (!fp) {
		printf("create/open file error\n");
		return -EINVAL;
	}

	fprintf(fp, "sip=<%s> dip=<%s> sport=<%d> dport=<%d> version=<%d>\n",
	st_opt.sip, st_opt.dip, st_opt.sport, st_opt.dport, st_opt.ip_version);

	fclose(fp);
	return 0;
}

/*
 * nss_udp_st_list()
 *	List NSS UDP speedtest rules
 */
static int nss_udp_st_list(void)
{
	FILE *fp = NULL;
	char *buffer = NULL;
	size_t size = 0;

	fp = fopen(NSS_UDP_ST_RULES, "r");
	if (!fp) {
		printf("create/open file error\n");
		return -EINVAL;
	}

	while ((getline(&buffer, &size, fp)) != -1) {
		printf("\n%s", buffer);
	}

	free(buffer);
	fclose(fp);
	return 0;
}

/*
 * nss_udp_st_clear()
 *	Clear NSS UDP speedtest rules
 */
static int nss_udp_st_clear(void)
{
	FILE *fp = NULL;

	fp = fopen(NSS_UDP_ST_RULES, "w");
	if (!fp) {
		printf("create/open file error\n");
		return -EINVAL;
	}

	fclose(fp);
	return 0;
}

/*
 * nss_udp_st_push_rules()
 *	Push NSS UDP speedtest rules to driver
 */
static int nss_udp_st_push_rules(void)
{
	FILE *fp = NULL;
	char *buffer = NULL;
	char *token = NULL;
	char *saveptr = NULL;
	size_t size = 0;
	int count = 0;
	int ret = 0;
	bool flag = true;

	fp = fopen(NSS_UDP_ST_RULES, "r");
	if (!fp) {
		printf("create/open file error\n");
		return -EINVAL;
	}

	while ((getline(&buffer, &size, fp)) != -1) {
		flag = true;
		count = 0;
		token=strtok_r(buffer, "<>", &saveptr);
		memset(&st_opt, 0, sizeof(st_opt));
		while(token != NULL) {
			flag = !flag;
			if (flag) {
				if (count == NSS_UDP_ST_SIP)
					strlcpy(st_opt.sip, token, sizeof(st_opt.sip));
				if (count == NSS_UDP_ST_DIP)
					strlcpy(st_opt.dip, token, sizeof(st_opt.dip));
				if (count == NSS_UDP_ST_SPORT)
					st_opt.sport=atoi(token);
				if (count == NSS_UDP_ST_DPORT)
					st_opt.dport=atoi(token);
				if (count == NSS_UDP_ST_FLAGS)
					st_opt.ip_version=atoi(token);

				count ++;
			}
			token = strtok_r(NULL, "<>", &saveptr);
		}

		ret = write(st_cfg.handle, &st_opt, sizeof(st_opt));
		if (ret < 0) {
			printf("invalid rule config option\n");
			printf("write error %d\n",ret);
			free(buffer);
			fclose(fp);
			return -EINVAL;
		}
	}

	free(buffer);
	fclose(fp);
	return 0;
}

/*
 * nss_udp_st_start()
 *	Send ioctl to start NSS UDP speedtest
 */
static int nss_udp_st_start(void)
{
	int ret = nss_udp_st_push_rules();
	if (ret) {
		printf("invalid rule config option\n");
		return -EINVAL;
	}

	if (st_cfg.type == NSS_UDP_ST_TX) {
		ret = ioctl(st_cfg.handle, NSS_UDP_ST_IOCTL_START_TX, &st_cfg.time);
	} else if (st_cfg.type == NSS_UDP_ST_RX) {
		ret = ioctl(st_cfg.handle, NSS_UDP_ST_IOCTL_START_RX);
	} else {
		printf("invalid type option\n");
		return -EINVAL;
	}

	if (ret < 0) {
		printf("ioctl error %d\n", ret);
		return -EINVAL;
	}

	return 0;
}

/*
 * nss_udp_st_stop()
 *	Send ioctl to stop NSS USP speedtest
 */
static int nss_udp_st_stop(void)
{
	int ret = ioctl(st_cfg.handle, NSS_UDP_ST_IOCTL_STOP);
	if (ret < 0) {
		printf("ioctl error %d\n", ret);
		return -EINVAL;
	}

	return 0;
}

/*
 * nss_udp_st_stats()
 *	Read NSS UDP speedtest results
 */
static int nss_udp_st_stats(void)
{
	int ret = 0;
	FILE *fp = NULL;
	long long bytes = 0;

	ret = read(st_cfg.handle, &st_stat, sizeof(st_stat));
	if (ret < 0) {
		printf("read error %d\n",ret);
		return -EINVAL;
	}

	if (st_cfg.type == NSS_UDP_ST_TX) {
		fp = fopen(NSS_UDP_ST_TX_STATS, "w");
		if (!fp) {
			printf("create/open file error\n");
			return -EINVAL;
		}

		fprintf(fp, "\nPacket Stats\n");
		fprintf(fp, "\ttx_packets = %lld packets\n",st_stat.p_stats.tx_packets);
		fprintf(fp, "\ttx_bytes   = %lld bytes\n",st_stat.p_stats.tx_bytes);
		bytes = st_stat.p_stats.tx_bytes;
	} else if (st_cfg.type == NSS_UDP_ST_RX) {
		fp = fopen(NSS_UDP_ST_RX_STATS, "w");
		if (!fp) {
			printf("create/open file error\n");
			return -EINVAL;
		}

		fprintf(fp, "\nPacket Stats\n\n");
		fprintf(fp, "\trx_packets = %lld packets\n",st_stat.p_stats.rx_packets);
		fprintf(fp, "\trx_bytes   = %lld bytes\n",st_stat.p_stats.rx_bytes);
		bytes = st_stat.p_stats.rx_bytes;
	} else {
		printf("type error\n");
		return -EINVAL;
	}

	fprintf(fp, "\nTime Stats\n");
	fprintf(fp, "\tstart time = %lld ms\n",st_stat.timer_stats[NSS_UDP_ST_STATS_TIME_START]);
	fprintf(fp, "\tcapture time = %lld ms\n",
		st_stat.timer_stats[NSS_UDP_ST_STATS_TIME_CURRENT]);
	fprintf(fp, "\telapsed time = %lld ms\n",
		st_stat.timer_stats[NSS_UDP_ST_STATS_TIME_ELAPSED]);

	fprintf(fp, "\nError Stats\n");
	fprintf(fp, "\tincorrect rate = %lld\n",
		st_stat.errors[NSS_UDP_ST_ERROR_INCORRECT_RATE]);
	fprintf(fp, "\tincorrect buffer size = %lld\n",
		st_stat.errors[NSS_UDP_ST_ERROR_INCORRECT_BUFFER_SIZE]);
	fprintf(fp, "\tmemory failure = %lld\n",
		st_stat.errors[NSS_UDP_ST_ERROR_MEMORY_FAILURE]);
	fprintf(fp, "\tpacket drop count = %lld\n",
		st_stat.errors[NSS_UDP_ST_ERROR_PACKET_DROP]);
	fprintf(fp, "\tincorrect ip version = %lld\n",
		st_stat.errors[NSS_UDP_ST_ERROR_INCORRECT_IP_VERSION]);

	fprintf(fp, "\nThroughput Stats\n");
	fprintf(fp, "\tthroughput  = %lld Mbps\n",
		(bytes * 8)/(st_stat.timer_stats[NSS_UDP_ST_STATS_TIME_ELAPSED] * 1000));
	fclose(fp);
	return 0;
}

/*
 * nss_udp_st_usage()
 *	Usage for command line arguments
 */
static void nss_udp_st_usage(void)
{
	printf("\nUsage:");
	printf("\n./nss_udp_st --mode <init> --rate <rate in Mbps> \
		--buffer_sz <buffer_size in bytes> --dscp <dscp> --net_dev <net_dev>");
	printf("\n./nss_udp_st --mode <create> --sip <sip> --dip <dip> \
		--sport <sport> --dport <dport> --version <4/6>");
	printf("\n./nss_udp_st --mode <start> --type <tx/rx> --time <time in seconds>");
	printf("\n./nss_udp_st --mode <stats> --type <tx/rx>");
	printf("\n./nss_udp_st --mode <list/clear/final>");
}

/*
 * nss_udp_st_get_opt()
 *	Parse command line arguments
 */
static int nss_udp_st_get_opt(int args, char **argv)
{
	int c = 0;
	int option_index = 0;

	while (1) {
		c = getopt_long_only(args, argv, "m:x:s:d:y:z:n:f:t:r:b:c",
			long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'm':
			strlcpy(st_cfg.mode, optarg, sizeof(st_cfg.mode));
			break;

		case 'x':
			if (!strcmp(optarg, "tx")) {
				st_cfg.type = NSS_UDP_ST_TX;
			} else if (!strcmp(optarg, "rx")) {
				st_cfg.type = NSS_UDP_ST_RX;
			} else {
				printf("invalid option for type (tx/rx)\n");
				return -EINVAL;
			}
			break;

		case 's':
			strlcpy(st_opt.sip, optarg, sizeof(st_opt.sip));
			break;

		case 'd':
			strlcpy(st_opt.dip, optarg, sizeof(st_opt.dip));
			break;

		case 'y':
			st_opt.sport = atoi(optarg);
			break;

		case 'z':
			st_opt.dport = atoi(optarg);
			break;

		case 'n':
			strlcpy(st_param.net_dev, optarg, sizeof(st_param.net_dev));
			break;

		case 'f':
			st_opt.ip_version = atoi(optarg);
			break;

		case 't':
			st_cfg.time = atoi(optarg);
			break;

		case 'r':
			st_param.rate = atoi(optarg);
			break;

		case 'b':
			st_param.buffer_sz = atoi(optarg);
			break;

		case 'c':
			st_param.dscp = atoi(optarg);
			break;

		case 'h':
			nss_udp_st_usage();
			break;

		default:
			nss_udp_st_usage();
			return -EINVAL;
		}
	}
	return 0;
}

/*
 * main()
 *	Invoke helper function based on command line arguments
 */
int main(int args, char **argv)
{

	memset(&st_param, 0, sizeof(st_param));
	memset(&st_opt, 0, sizeof(st_opt));
	memset(&st_cfg, 0, sizeof(st_cfg));
	memset(&st_stat, 0, sizeof(st_stat));

	if (nss_udp_st_get_opt(args, argv)) {
		printf("invalid command line options\n");
		return -EINVAL;
	}

	if (!strcmp(st_cfg.mode,"init")) {
		system("insmod nss-udp-st.ko");
		st_cfg.handle = open(NSS_UDP_ST_DEV, O_RDWR);
		nss_udp_st_init();
		close(st_cfg.handle);
	} else if (!strcmp(st_cfg.mode,"final")) {
		nss_udp_st_final();
	} else if (!strcmp(st_cfg.mode,"create")) {
		nss_udp_st_create();
	} else if (!strcmp(st_cfg.mode,"list")) {
		nss_udp_st_list();
	} else if (!strcmp(st_cfg.mode,"clear")) {
		nss_udp_st_clear();
	} else if (!strcmp(st_cfg.mode,"start")) {
		st_cfg.handle = open(NSS_UDP_ST_DEV, O_RDWR);
		nss_udp_st_start();
		close(st_cfg.handle);
	} else if (!strcmp(st_cfg.mode,"stop")) {
		st_cfg.handle = open(NSS_UDP_ST_DEV, O_RDWR);
		nss_udp_st_stop();
		close(st_cfg.handle);
	} else if (!strcmp(st_cfg.mode,"stats")) {
		st_cfg.handle = open(NSS_UDP_ST_DEV, O_RDWR);
		nss_udp_st_stats();
		close(st_cfg.handle);
	} else {
		printf("invalid command line options for mode\n");
		return -EINVAL;
	}
	return 0;
}
