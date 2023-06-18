include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-nss-clients
PKG_RELEASE:=2
PKG_SOURCE_URL:=https://git.codelinaro.org/clo/qsdk/oss/lklm/nss-clients.git
PKG_SOURCE_DATE:=2020-10-29
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=ef082a735fad96bd2f6f59b94d6ea81defc4796e
PKG_MIRROR_HASH:=9375f2bbdd17826b6ddebc77607ec73c98626570243a9831a1e34e1051eb436c
PKG_BUILD_DEPENDS:=qca-nss-drv
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

# Keep default as ipq806x for branches that does not have subtarget framework
ifeq ($(CONFIG_TARGET_ipq),y)
subtarget:=$(SUBTARGET)
else
subtarget:=$(CONFIG_TARGET_BOARD)
endif

ifneq (, $(findstring $(subtarget), "ipq807x" "ipq807x_64" "ipq60xx" "ipq60xx_64"))
# DTLS Manager v2.0 for Hawkeye/Cypress
  DTLSMGR_DIR:=v2.0
# IPsec Manager v2.0 for Hawkeye/Cypress
  IPSECMGR_DIR:=v2.0
# KLIPS plugin
  IPSECMGR_KLIPS:= $(PKG_BUILD_DIR)/ipsecmgr/$(IPSECMGR_DIR)/plugins/klips/qca-nss-ipsec-klips.ko
else
# DTLS Manager v1.0 for Akronite.
  DTLSMGR_DIR:=v1.0
# IPsec Manager v1.0 for Akronite.
  IPSECMGR_DIR:=v1.0
# KLIPS plugin not needed
  IPSECMGR_KLIPS:=
endif

define KernelPackage/qca-nss-drv-tun6rd
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS (connection manager) - tun6rd
  DEPENDS:=+@NSS_DRV_TUN6RD_ENABLE +kmod-sit +6rd \
		+PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
  FILES:=$(PKG_BUILD_DIR)/qca-nss-tun6rd.ko
  AUTOLOAD:=$(call AutoLoad,60,qca-nss-tun6rd)
endef

define KernelPackage/qca-nss-drv-tun6rd/description
Kernel modules for NSS connection manager - Support for 6rd tunnel
endef

define KernelPackage/qca-nss-drv-dtlsmgr
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS (connection manager) - dtlsmgr
  DEPENDS:=+@NSS_DRV_DTLS_ENABLE \
		+PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv \
		+PACKAGE_kmod-qca-nss-cfi-cryptoapi:kmod-qca-nss-cfi-cryptoapi
  FILES:=$(PKG_BUILD_DIR)/dtls/$(DTLSMGR_DIR)/qca-nss-dtlsmgr.ko
endef

define KernelPackage/qca-nss-drv-dtls/description
Kernel modules for NSS connection manager - Support for DTLS sessions
endef

define KernelPackage/qca-nss-drv-tlsmgr
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS (connection manager) - tlsmgr
  DEPENDS:=@TARGET_ipq_ipq807x||TARGET_ipq_ipq807x_64||TARGET_ipq807x||TARGET_ipq807x_64||TARGET_ipq_ipq60xx||TARGET_ipq_ipq60xx_64 +kmod-qca-nss-cfi-cryptoapi +@NSS_DRV_TLS_ENABLE
  FILES:=$(PKG_BUILD_DIR)/tls/qca-nss-tlsmgr.ko
endef

define KernelPackage/qca-nss-drv-tls/description
Kernel modules for NSS connection manager - Support for TLS sessions
endef

define KernelPackage/qca-nss-drv-l2tpv2
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS (connection manager) - l2tp
  DEPENDS:=+@NSS_DRV_L2TP_ENABLE +kmod-ppp +kmod-l2tp \
		+PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
  FILES:=$(PKG_BUILD_DIR)/l2tp/l2tpv2/qca-nss-l2tpv2.ko
  KCONFIG:=CONFIG_L2TP=y
  AUTOLOAD:=$(call AutoLoad,51,qca-nss-l2tpv2)
endef

define KernelPackage/qca-nss-drv-l2tp/description
Kernel modules for NSS connection manager - Support for l2tp tunnel
endef

define KernelPackage/qca-nss-drv-pptp
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS (connection manager) - PPTP
  DEPENDS:=+@NSS_DRV_PPTP_ENABLE +kmod-pptp \
		+PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
  FILES:=$(PKG_BUILD_DIR)/pptp/qca-nss-pptp.ko
  AUTOLOAD:=$(call AutoLoad,51,qca-nss-pptp)
endef

define KernelPackage/qca-nss-drv-pptp/description
Kernel modules for NSS connection manager - Support for PPTP tunnel
endef

define KernelPackage/qca-nss-drv-pppoe
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS (connection manager) - PPPoE
  DEPENDS:=+@NSS_DRV_PPPOE_ENABLE +kmod-pppoe \
  		+PACKAGE_kmod-bonding:kmod-bonding \
		+PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
  FILES:=$(PKG_BUILD_DIR)/pppoe/qca-nss-pppoe.ko
  AUTOLOAD:=$(call AutoLoad,51,qca-nss-pppoe)
endef

define KernelPackage/qca-nss-drv-pppoe/description
Kernel modules for NSS connection manager - Support for PPPoE
endef

define KernelPackage/qca-nss-drv-map-t
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS (connection manager) - MAP-T
  DEPENDS:=+@NSS_DRV_MAPT_ENABLE +PACKAGE_kmod-qca-nat46:kmod-qca-nat46 \
		+PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
  FILES:=$(PKG_BUILD_DIR)/map/map-t/qca-nss-map-t.ko
  AUTOLOAD:=$(call AutoLoad,51,qca-nss-map-t)
endef

define KernelPackage/qca-nss-drv-map-t/description
Kernel modules for NSS connection manager - Support for MAP-T
endef

define KernelPackage/qca-nss-drv-gre
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS (connection manager) - GRE
  DEPENDS:=@TARGET_ipq_ipq806x||TARGET_ipq806x||TARGET_ipq_ipq807x||TARGET_ipq_ipq807x_64||TARGET_ipq807x||TARGET_ipq807x_64||TARGET_ipq_ipq60xx||TARGET_ipq_ipq60xx_64||TARGET_ipq_ipq50xx||TARGET_ipq_ipq50xx_64 \
	   +@NSS_DRV_GRE_ENABLE +kmod-gre6 \
	   +PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
  FILES:=$(PKG_BUILD_DIR)/gre/qca-nss-gre.ko $(PKG_BUILD_DIR)/gre/test/qca-nss-gre-test.ko
  AUTOLOAD:=$(call AutoLoad,51,qca-nss-gre)
endef

define KernelPackage/qca-nss-drv-gre/description
Kernel modules for NSS connection manager - Support for GRE
endef

define KernelPackage/qca-nss-drv-tunipip6
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS (connection manager) - DS-lite and ipip6 Tunnel
  DEPENDS:=+@NSS_DRV_TUNIPIP6_ENABLE +kmod-iptunnel6 +kmod-ip6-tunnel \
		+PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
  FILES:=$(PKG_BUILD_DIR)/qca-nss-tunipip6.ko
  AUTOLOAD:=$(call AutoLoad,60,qca-nss-tunipip6)
endef

define KernelPackage/qca-nss-drv-tunipip6/description
Kernel modules for NSS connection manager
Add support for DS-lite and ipip6 tunnel
endef

define KernelPackage/qca-nss-drv-profile
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  DEPENDS:=+@NSS_DRV_PROFILE_ENABLE \
		   +PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
  TITLE:=Profiler for QCA NSS driver (IPQ806x)
  FILES:=$(PKG_BUILD_DIR)/profiler/qca-nss-profile-drv.ko
endef

define KernelPackage/qca-nss-drv-profile/description
This package contains a NSS driver profiler for QCA chipset
endef

define KernelPackage/qca-nss-drv-ipsecmgr
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS (ipsec manager) - ipsecmgr
  DEPENDS:=@TARGET_ipq806x||TARGET_ipq807x \
		   +@NSS_DRV_TSTAMP_ENABLE \
		   +@NSS_DRV_IPSEC_ENABLE \
		   +PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv \
		   +PACKAGE_kmod-qca-nss-cfi-cryptoapi:kmod-qca-nss-cfi-cryptoapi
ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-l2tpv2),)
  DEPENDS+=+kmod-qca-nss-drv-l2tpv2
endif
  FILES:=$(PKG_BUILD_DIR)/ipsecmgr/$(IPSECMGR_DIR)/qca-nss-ipsecmgr.ko	$(IPSECMGR_KLIPS)
  AUTOLOAD:=$(call AutoLoad,60,qca-nss-ipsecmgr)
endef

define KernelPackage/qca-nss-drv-ipsecmgr/description
Kernel module for NSS IPsec offload manager
endef

define KernelPackage/qca-nss-drv-portifmgr
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS (qca-nss-drv-portifmgr)
  DEPENDS:=+@NSS_DRV_PORTID_ENABLE +kmod-qca-nss-gmac \
		+PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
  FILES:=$(PKG_BUILD_DIR)/portifmgr/qca-nss-portifmgr.ko
endef

define KernelPackage/qca-nss-drv-portifmgr/Description
NSS Kernel module for Port interface manager
endef

define KernelPackage/qca-nss-drv-bridge-mgr
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS bridge manager
  DEPENDS:=@TARGET_ipq_ipq807x||TARGET_ipq_ipq807x_64||TARGET_ipq807x||TARGET_ipq_ipq60xx||TARGET_ipq_ipq60xx_64||TARGET_ipq60xx \
		+TARGET_ipq_ipq807x:kmod-qca-nss-drv-vlan-mgr \
		+TARGET_ipq_ipq807x_64:kmod-qca-nss-drv-vlan-mgr \
		+TARGET_ipq807x:kmod-qca-nss-drv-vlan-mgr \
		+TARGET_ipq60xx:kmod-qca-nss-drv-vlan-mgr \
		+TARGET_ipq_ipq60xx:kmod-qca-nss-drv-vlan-mgr \
		+TARGET_ipq_ipq60xx_64:kmod-qca-nss-drv-vlan-mgr \
		+PACKAGE_kmod-bonding:kmod-bonding \
		+PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv \
		+@NSS_DRV_BRIDGE_ENABLE
ifneq ($(CONFIG_PACKAGE_kmod-qca-ovsmgr),)
  DEPENDS+=kmod-qca-ovsmgr
endif
  FILES:=$(PKG_BUILD_DIR)/bridge/qca-nss-bridge-mgr.ko
  AUTOLOAD:=$(call AutoLoad,51,qca-nss-bridge-mgr)
endef

define KernelPackage/qca-nss-drv-bridge-mgr/description
Kernel modules for NSS bridge manager
endef

define KernelPackage/qca-nss-drv-vlan-mgr
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS vlan manager
  DEPENDS:=@TARGET_ipq_ipq807x||TARGET_ipq_ipq806x||TARGET_ipq807x||TARGET_ipq_ipq60xx||TARGET_ipq_ipq60xx_64||TARGET_ipq60xx \
		+PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv \
	   +@NSS_DRV_VLAN_ENABLE \
	   +PACKAGE_kmod-bonding:kmod-bonding
  FILES:=$(PKG_BUILD_DIR)/vlan/qca-nss-vlan.ko
  AUTOLOAD:=$(call AutoLoad,51,qca-nss-vlan)
endef

define KernelPackage/qca-nss-drv-vlan-mgr/description
Kernel modules for NSS vlan manager
endef

define KernelPackage/qca-nss-drv-qdisc
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Qdisc for configuring shapers in NSS
  DEPENDS:=+@NSS_DRV_SHAPER_ENABLE +@NSS_DRV_IGS_ENABLE \
		+PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
  FILES:=$(PKG_BUILD_DIR)/nss_qdisc/qca-nss-qdisc.ko
  KCONFIG:=CONFIG_NET_CLS_ACT=y
  AUTOLOAD:=$(call AutoLoad,58,qca-nss-qdisc)
endef

define KernelPackage/qca-nss-drv-qdisc/description
Linux qdisc that aids in configuring shapers in the NSS
endef

define KernelPackage/qca-nss-drv-igs
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Action for offloading traffic to an IFB interface to perform ingress shaping.
  DEPENDS:=@TARGET_ipq806x||TARGET_ipq_ipq807x||TARGET_ipq_ipq807x_64||TARGET_ipq_ipq60xx||TARGET_ipq_ipq60xx_64||TARGET_ipq_ipq50xx||TARGET_ipq_ipq50xx_64 \
	+@NSS_DRV_IGS_ENABLE +kmod-sched-core +kmod-ifb +kmod-qca-nss-drv-qdisc \
	+PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
  FILES:=$(PKG_BUILD_DIR)/nss_qdisc/igs/act_nssmirred.ko
endef

define KernelPackage/qca-nss-drv-igs/description
Linux action that helps in offloading traffic to an IFB interface to perform ingress shaping.
endef

define KernelPackage/qca-nss-drv-lag-mgr
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS LAG manager
  DEPENDS:=+@NSS_DRV_LAG_ENABLE \
	   +TARGET_ipq_ipq807x:kmod-qca-nss-drv-vlan-mgr \
	   +TARGET_ipq_ipq807x_64:kmod-qca-nss-drv-vlan-mgr \
	   +TARGET_ipq807x:kmod-qca-nss-drv-vlan-mgr \
	   +TARGET_ipq_ipq60xx:kmod-qca-nss-drv-vlan-mgr \
	   +TARGET_ipq_ipq60xx_64:kmod-qca-nss-drv-vlan-mgr \
	   +TARGET_ipq60xx:kmod-qca-nss-drv-vlan-mgr \
	   +PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
  FILES:=$(PKG_BUILD_DIR)/lag/qca-nss-lag-mgr.ko
  AUTOLOAD:=$(call AutoLoad,51,qca-nss-lag-mgr)
endef

define KernelPackage/qca-nss-drv-lag-mgr/description
Kernel modules for NSS LAG manager
endef

define KernelPackage/qca-nss-drv-netlink
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  DEPENDS:=@TARGET_ipq806x||TARGET_ipq807x||TARGET_ipq_ipq807x_64||TARGET_ipq_ipq60xx||TARGET_ipq_ipq60xx_64||TARGET_ipq60xx||TARGET_ipq_ipq50xx||TARGET_ipq_ipq50xx_64||TARGET_ipq50xx \
		+PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv \
  		+@NSS_DRV_GRE_REDIR_ENABLE
  TITLE:=NSS NETLINK Manager for QCA NSS driver
  FILES:=$(PKG_BUILD_DIR)/netlink/qca-nss-netlink.ko
endef

define KernelPackage/qca-nss-drv-netlink/description
Kernel module for NSS netlink manager
endef

define KernelPackage/qca-nss-drv-ovpn-mgr
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for NSS OpenVPN manager
  DEPENDS:=+@NSS_DRV_OVPN_ENABLE +kmod-qca-nss-drv +kmod-qca-nss-cfi-cryptoapi +kmod-tun +kmod-ipt-conntrack \
	  @TARGET_ipq_ipq807x||TARGET_ipq_ipq807x_64||TARGET_ipq_ipq60xx||TARGET_ipq_ipq60xx_64
  FILES:=$(PKG_BUILD_DIR)/openvpn/src/qca-nss-ovpn-mgr.ko
endef

define KernelPackage/qca-nss-drv-ovpn-mgr/description
Kernel module for NSS OpenVPN manager
endef

define KernelPackage/qca-nss-drv-ovpn-link
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  TITLE:=Kernel driver for interfacing NSS OpenVPN manager with ECM
  DEPENDS:=+kmod-qca-nss-drv-ovpn-mgr +@PACKAGE_kmod-qca-nss-ecm-premium \
	  @TARGET_ipq_ipq807x||TARGET_ipq_ipq807x_64||TARGET_ipq_ipq60xx||TARGET_ipq_ipq60xx_64
  FILES:=$(PKG_BUILD_DIR)/openvpn/plugins/qca-nss-ovpn-link.ko
endef

define KernelPackage/qca-nss-drv-ovpn-link/description
This module registers with ECM and communicates with NSS OpenVPN manager for supporting OpenVPN offload.
endef

define KernelPackage/qca-nss-drv-pvxlanmgr
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  DEPENDS:=+@NSS_DRV_PVXLAN_ENABLE +PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
  TITLE:=NSS PVXLAN Manager for QCA NSS driver
  FILES:=$(PKG_BUILD_DIR)/pvxlanmgr/qca-nss-pvxlanmgr.ko
endef

define KernelPackage/qca-nss-drv-pvxlanmgr/description
Kernel module for managing NSS PVxLAN
endef

define KernelPackage/qca-nss-drv-eogremgr
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  DEPENDS:=+@NSS_DRV_GRE_ENABLE +PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv +kmod-qca-nss-drv-gre
  TITLE:=NSS EOGRE Manager for QCA NSS driver
  FILES:=$(PKG_BUILD_DIR)/eogremgr/qca-nss-eogremgr.ko
endef

define KernelPackage/qca-nss-drv-eogremgr/description
Kernel module for managing NSS EoGRE
endef

define KernelPackage/qca-nss-drv-clmapmgr
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  DEPENDS:=+@NSS_DRV_CLMAP_ENABLE +PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv +kmod-qca-nss-drv-eogremgr
  TITLE:=NSS clmap Manager for QCA NSS driver
  FILES:=$(PKG_BUILD_DIR)/clmapmgr/qca-nss-clmapmgr.ko
endef

define KernelPackage/qca-nss-drv-clmapmgr/description
Kernel module for managing NSS clmap
endef

# define KernelPackage/qca-nss-drv-vxlanmgr
#   SECTION:=kernel
#   CATEGORY:=Kernel modules
#   SUBMENU:=Network Devices
#   DEPENDS:=+@NSS_DRV_VXLAN_ENABLE +PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv +kmod-vxlan
#   TITLE:=NSS VxLAN Manager for QCA NSS driver
#   FILES:=$(PKG_BUILD_DIR)/vxlanmgr/qca-nss-vxlanmgr.ko
#   AUTOLOAD:=$(call AutoLoad,51,qca-nss-vxlanmgr)
# endef
#
# define KernelPackage/qca-nss-drv-vxlanmgr/description
# Kernel module for managing NSS VxLAN
# endef

# define KernelPackage/qca-nss-drv-match
#  SECTION:=kernel
#  CATEGORY:=Kernel modules
#  SUBMENU:=Network Devices
#  DEPENDS:=+@NSS_DRV_MATCH_ENABLE +PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
#  TITLE:=NSS Match for QCA NSS driver
#  FILES:=$(PKG_BUILD_DIR)/match/qca-nss-match.ko
# endef
#
# define KernelPackage/qca-nss-drv-match/description
# Kernel module for managing NSS Match
# endef
#
# define KernelPackage/qca-nss-drv-mirror
#  SECTION:=kernel
#  CATEGORY:=Kernel modules
#  SUBMENU:=Network Devices
#  TITLE:=Module for mirroring packets from NSS to host.
#  DEPENDS:=+@NSS_DRV_MIRROR_ENABLE +PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
#  FILES:=$(PKG_BUILD_DIR)/mirror/qca-nss-mirror.ko
# endef
#
# define KernelPackage/qca-nss-drv-mirror/Description
# Kernel module for managing NSS Mirror
# endef

# define KernelPackage/qca-nss-drv-wifi-meshmgr
#   SECTION:=kernel
#   CATEGORY:=Kernel modules
#   SUBMENU:=Network Devices
#   DEPENDS:=+@NSS_DRV_WIFI_ENABLE +PACKAGE_kmod-qca-nss-drv:kmod-qca-nss-drv
#   TITLE:=NSS WiFi-Mesh Manager for QCA NSS driver
#   FILES:=$(PKG_BUILD_DIR)/wifi_meshmgr/qca-nss-wifi-meshmgr.ko
#   AUTOLOAD:=$(call AutoLoad,51,qca-nss-wifi-meshmgr)
# endef

# define KernelPackage/qca-nss-drv-wifi-meshmgr/Description
# Kernel module for WiFi Mesh manager
# endef

define Build/InstallDev/qca-nss-clients
	$(INSTALL_DIR) $(1)/usr/include/qca-nss-clients
	$(CP) $(PKG_BUILD_DIR)/netlink/include/* $(1)/usr/include/qca-nss-clients/
	$(CP) $(PKG_BUILD_DIR)/exports/* $(1)/usr/include/qca-nss-clients/
endef

define Build/InstallDev
	$(call Build/InstallDev/qca-nss-clients,$(1))
endef

define KernelPackage/qca-nss-drv-ovpn-mgr/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/qca-nss-ovpn.init $(1)/etc/init.d/qca-nss-ovpn
endef

define KernelPackage/qca-nss-drv-ipsecmgr/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/qca-nss-ipsec $(1)/etc/init.d/qca-nss-ipsec
endef

define KernelPackage/qca-nss-drv-igs/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/qca-nss-mirred.init $(1)/etc/init.d/qca-nss-mirred
endef

EXTRA_CFLAGS+= \
	-I$(STAGING_DIR)/usr/include/qca-nss-drv \
	-I$(STAGING_DIR)/usr/include/qca-nss-crypto \
	-I$(STAGING_DIR)/usr/include/qca-nss-cfi \
	-I$(STAGING_DIR)/usr/include/qca-nss-gmac \
	-I$(STAGING_DIR)/usr/include/qca-nss-ecm \
	-I$(STAGING_DIR)/usr/include/qca-ssdk \
	-I$(STAGING_DIR)/usr/include/qca-ssdk/fal \
	-I$(STAGING_DIR)/usr/include/nat46

# Build individual packages if selected
ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-portifmgr),)
MAKE_OPTS+=portifmgr=y
EXTRA_CFLAGS += -DNSS_PORTIFMGR_REF_AP148 -I$(PKG_BUILD_DIR)/portifmgr
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-profile),)
MAKE_OPTS+=profile=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-tun6rd),)
MAKE_OPTS+=tun6rd=m
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-dtlsmgr),)
MAKE_OPTS+=dtlsmgr=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-tlsmgr),)
MAKE_OPTS+=tlsmgr=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-l2tpv2),)
MAKE_OPTS+=l2tpv2=y
EXTRA_CFLAGS += -DNSS_L2TPV2_ENABLED
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-pptp),)
MAKE_OPTS+=pptp=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-map-t),)
MAKE_OPTS+=map-t=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-tunipip6),)
MAKE_OPTS+=tunipip6=m
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-qdisc),)
MAKE_OPTS+=qdisc=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-igs),)
MAKE_OPTS+=igs=y
EXTRA_CFLAGS+=-DNSS_IGS_DEBUG_LEVEL=4
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-ipsecmgr),)
EXTRA_CFLAGS+= -I$(PKG_BUILD_DIR)/exports \
		-I$(STAGING_DIR)/usr/include/qca-nss-ecm
MAKE_OPTS+=ipsecmgr=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-bridge-mgr),)
MAKE_OPTS+=bridge-mgr=y
#enable OVS bridge if ovsmgr is enabled
ifneq ($(CONFIG_PACKAGE_kmod-qca-ovsmgr),)
MAKE_OPTS+= NSS_BRIDGE_MGR_OVS_ENABLE=y
EXTRA_CFLAGS+= -I$(STAGING_DIR)/usr/include/qca-ovsmgr
endif
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-vlan-mgr),)
MAKE_OPTS+=vlan-mgr=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-lag-mgr),)
MAKE_OPTS+=lag-mgr=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-gre),)
EXTRA_CFLAGS+= -I$(PKG_BUILD_DIR)/exports
MAKE_OPTS+=gre=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-pppoe),)
MAKE_OPTS+=pppoe=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-netlink),)
MAKE_OPTS+=netlink=y

ifeq ($(CONFIG_KERNEL_IPQ_MEM_PROFILE),256)
EXTRA_CFLAGS+= -DNSS_NETLINK_UDP_ST_NO_RMNET_SUPPORT
else ifeq ($(CONFIG_LOWMEM_FLASH),y)
EXTRA_CFLAGS+= -DNSS_NETLINK_UDP_ST_NO_RMNET_SUPPORT
endif
endif

# ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-ovpn-mgr),)
# MAKE_OPTS+=ovpn-mgr=y
# endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-ovpn-link),)
MAKE_OPTS+=ovpn-link=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-pvxlanmgr),)
MAKE_OPTS+=pvxlanmgr=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-eogremgr),)
MAKE_OPTS+=eogremgr=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-clmapmgr),)
MAKE_OPTS+=clmapmgr=y
endif

# ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-vxlanmgr),)
# MAKE_OPTS+=vxlanmgr=y
# EXTRA_CFLAGS += -DNSS_VXLAN_ENABLED
# endif

# ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-match),)
# MAKE_OPTS+=match=y
# endif

define Build/Compile
	+$(MAKE) $(PKG_JOBS) -C "$(LINUX_DIR)" $(strip $(MAKE_OPTS)) \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		$(KERNEL_MAKE_FLAGS) \
		$(PKG_MAKE_FLAGS) \
		M="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		SoC="$(subtarget)" \
		DTLSMGR_DIR="$(DTLSMGR_DIR)" \
		IPSECMGR_DIR="$(IPSECMGR_DIR)" \
		modules
endef

$(eval $(call KernelPackage,qca-nss-drv-profile))
$(eval $(call KernelPackage,qca-nss-drv-tun6rd))
$(eval $(call KernelPackage,qca-nss-drv-dtlsmgr))
$(eval $(call KernelPackage,qca-nss-drv-l2tpv2))
$(eval $(call KernelPackage,qca-nss-drv-pptp))
$(eval $(call KernelPackage,qca-nss-drv-pppoe))
$(eval $(call KernelPackage,qca-nss-drv-map-t))
$(eval $(call KernelPackage,qca-nss-drv-tunipip6))
$(eval $(call KernelPackage,qca-nss-drv-qdisc))
$(eval $(call KernelPackage,qca-nss-drv-igs))
$(eval $(call KernelPackage,qca-nss-drv-portifmgr))
$(eval $(call KernelPackage,qca-nss-drv-netlink))
$(eval $(call KernelPackage,qca-nss-drv-ipsecmgr))
$(eval $(call KernelPackage,qca-nss-drv-bridge-mgr))
$(eval $(call KernelPackage,qca-nss-drv-vlan-mgr))
$(eval $(call KernelPackage,qca-nss-drv-lag-mgr))
$(eval $(call KernelPackage,qca-nss-drv-gre))
$(eval $(call KernelPackage,qca-nss-drv-ovpn-mgr))
$(eval $(call KernelPackage,qca-nss-drv-ovpn-link))
$(eval $(call KernelPackage,qca-nss-drv-pvxlanmgr))
$(eval $(call KernelPackage,qca-nss-drv-eogremgr))
$(eval $(call KernelPackage,qca-nss-drv-clmapmgr))
# $(eval $(call KernelPackage,qca-nss-drv-vxlanmgr))
# $(eval $(call KernelPackage,qca-nss-drv-match))
$(eval $(call KernelPackage,qca-nss-drv-tlsmgr))
