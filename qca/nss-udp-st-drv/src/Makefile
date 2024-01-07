#
# Makefile for NSS UDP Speed Test
#
obj ?= .

NSS_UDP_ST_BASE_OBJS := nss_udp_st_drv.o nss_udp_st_rx.o nss_udp_st_tx.o nss_udp_st_ip.o

obj-m += nss-udp-st.o

#
# Base files
#
nss-udp-st-objs := $(NSS_UDP_ST_BASE_OBJS)

ccflags-y += -Werror -Wall -I$(obj) -I$(obj)/exports
