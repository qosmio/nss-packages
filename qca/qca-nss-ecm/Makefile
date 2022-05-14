include $(TOPDIR)/rules.mk

PKG_NAME:=qca-nss-ecm
PKG_RELEASE:=$(AUTORELEASE)

PKG_SOURCE_URL:=https://git.codelinaro.org/clo/qsdk/oss/lklm/qca-nss-ecm.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_DATE:=2022-07-09
PKG_SOURCE_VERSION:=83b4e6266f94e1084acc69c97706d0c86a44cfe3
PKG_MIRROR_HASH:=62d87358f3cbb8266ebc04000980516cc4c95025ed6d6d332e54d6c18f2e2510

PKG_BUILD_PARALLEL:=1
PKG_FLAGS:=nonshared

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

define KernelPackage/qca-nss-ecm
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Support
  DEPENDS:=@(TARGET_ipq807x||TARGET_ipq60xx) \
  	+iptables-mod-extra \
	+iptables-mod-physdev \
  	+kmod-qca-nss-drv \
	+kmod-ipt-conntrack \
	+kmod-ipt-physdev \
	+kmod-ppp \
	+kmod-pppoe \
	+kmod-qca-mcs
  TITLE:=QCA NSS Enhanced Connection Manager (ECM)
  FILES:=$(PKG_BUILD_DIR)/ecm.ko
  KCONFIG:=CONFIG_BRIDGE_NETFILTER=y \
		   CONFIG_NF_CONNTRACK_EVENTS=y \
		   CONFIG_NF_CONNTRACK_DSCPREMARK_EXT=y
endef

define KernelPackage/qca-nss-ecm/Description
This package contains the QCA NSS Enhanced Connection Manager
endef

define KernelPackage/qca-nss-ecm/install
	$(INSTALL_DIR) $(1)/etc/firewall.d $(1)/etc/init.d $(1)/usr/bin $(1)/lib/netifd/offload $(1)/etc/config $(1)/etc/uci-defaults $(1)/etc/sysctl.d
	$(INSTALL_DATA) ./files/qca-nss-ecm.firewall $(1)/etc/firewall.d/qca-nss-ecm
	$(INSTALL_BIN) ./files/qca-nss-ecm.init $(1)/etc/init.d/qca-nss-ecm
	$(INSTALL_BIN) ./files/ecm_dump.sh $(1)/usr/bin/
	$(INSTALL_BIN) ./files/on-demand-down $(1)/lib/netifd/offload/on-demand-down
	$(INSTALL_DATA) ./files/qca-nss-ecm.uci $(1)/etc/config/ecm
	$(INSTALL_DATA) ./files/qca-nss-ecm.defaults $(1)/etc/uci-defaults/99-qca-nss-ecm
	$(INSTALL_BIN) ./files/qca-nss-ecm.sysctl $(1)/etc/sysctl.d/qca-nss-ecm.conf
	echo 'net.netfilter.nf_conntrack_max=8192' >> $(1)/etc/sysctl.d/qca-nss-ecm.conf
endef

EXTRA_CFLAGS+=-I$(STAGING_DIR)/usr/include/qca-nss-drv

ifneq (, $(findstring $(CONFIG_TARGET_BOARD), "ipq807x" "ipq60xx"))
ECM_MAKE_OPTS:=ECM_IPV6_ENABLE=y
ECM_MAKE_OPTS+=ECM_FRONT_END_NSS_ENABLE=y \
		ECM_FRONT_END_SFE_ENABLE=n \
		ECM_NON_PORTED_SUPPORT_ENABLE=y \
		ECM_MULTICAST_ENABLE=n \
		ECM_INTERFACE_BOND_ENABLE=n \
		ECM_INTERFACE_IPSEC_ENABLE=n \
		ECM_INTERFACE_PPTP_ENABLE=n \
		ECM_INTERFACE_PPPOE_ENABLE=y \
		ECM_INTERFACE_L2TPV2_ENABLE=n \
		ECM_INTERFACE_GRE_TAP_ENABLE=n \
		ECM_INTERFACE_GRE_TUN_ENABLE=n \
		ECM_INTERFACE_SIT_ENABLE=n \
		ECM_INTERFACE_TUNIPIP6_ENABLE=n \
		ECM_INTERFACE_RAWIP_ENABLE=n \
		ECM_INTERFACE_VLAN_ENABLE=y \
		ECM_CLASSIFIER_MARK_ENABLE=y \
		ECM_CLASSIFIER_DSCP_ENABLE=y \
		ECM_CLASSIFIER_PCC_ENABLE=n \
		ECM_BAND_STEERING_ENABLE=n
endif

# Variant with additional features enabled for noload profile
define KernelPackage/qca-nss-ecm-noload
$(call KernelPackage/qca-nss-ecm)
  TITLE+= (with noload features)
  PROVIDES:=kmod-qca-nss-ecm
  VARIANT:=noload
  DEPENDS+=+kmod-bonding
endef

define KernelPackage/qca-nss-ecm-noload/Description
  $(call KernelPackage/qca-nss-ecm/Description)
  When selected, this package installs the driver, but does not load it at init.
endef

define KernelPackage/qca-nss-ecm-noload/install
$(call KernelPackage/qca-nss-ecm/install, $(1))
	#
	# Remove the START line from the init script, so that the symlink
	# in the /etc/rc.d directory is not created.
	#
	sed -i '/START=/d' $(1)/etc/init.d/qca-nss-ecm
endef

ifneq ($(CONFIG_PACKAGE_kmod-qca-mcs),)
ECM_MAKE_OPTS+=ECM_MULTICAST_ENABLE=y
endif

define Build/InstallDev
	mkdir -p $(1)/usr/include/qca-nss-ecm
	$(CP) $(PKG_BUILD_DIR)/exports/* $(1)/usr/include/qca-nss-ecm
endef

define Build/Compile
	+$(MAKE) -C "$(LINUX_DIR)" $(strip $(ECM_MAKE_OPTS)) \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		M="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS) -Wno-error=unused-function " \
		SoC=$(CONFIG_TARGET_BOARD) \
		$(KERNEL_MAKE_FLAGS) \
		$(PKG_JOBS) \
		modules
endef

$(eval $(call KernelPackage,qca-nss-ecm))
$(eval $(call KernelPackage,qca-nss-ecm-noload))
