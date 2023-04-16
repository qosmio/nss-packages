include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-nss-ecm
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://git.codelinaro.org/clo/qsdk/oss/lklm/qca-nss-ecm.git
PKG_SOURCE_DATE:=2023-01-20
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=db66c47
PKG_MIRROR_HASH:=d4fd709914b37980c14b31fc6cb19f3ffdd4b8ff9d99c1d93ee70d2845c00af7
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

LOCAL_VARIANT=$(patsubst qca-nss-ecm-%,%,$(patsubst qca-nss-ecm-%,%,$(BUILD_VARIANT)))

ifeq ($(CONFIG_QCA_NSS_ECM_EXAMPLES_PCC),y)
       ECM_MAKE_OPTS+=ECM_CLASSIFIER_PCC_ENABLE=y
       FILES_EXAMPLES=$(PKG_BUILD_DIR)/examples/ecm_pcc_test.ko
endif

ifeq ($(CONFIG_QCA_NSS_ECM_EXAMPLES_MARK),y)
       FILES_EXAMPLES+=$(PKG_BUILD_DIR)/examples/ecm_mark_test.ko
endif

#Explicitly enable OVS external module, if ovsmgr is enabled.
ifneq ($(CONFIG_PACKAGE_kmod-qca-ovsmgr),)
CONFIG_QCA_NSS_ECM_OVS=y
endif

ifeq ($(CONFIG_QCA_NSS_ECM_OVS),y)
       FILES_EXAMPLES+=$(PKG_BUILD_DIR)/examples/ecm_ovs.ko
endif

define KernelPackage/qca-nss-ecm/Default
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Support
  TITLE:=QCA NSS Enhanced Connection Manager (ECM)
  FILES:=$(PKG_BUILD_DIR)/*.ko $(FILES_EXAMPLES)
  KCONFIG:=CONFIG_BRIDGE_NETFILTER=y \
	CONFIG_NF_CONNTRACK_EVENTS=y \
	CONFIG_NF_CONNTRACK_CHAIN_EVENTS=y \
	CONFIG_NF_CONNTRACK_DSCPREMARK_EXT=y
  MENU:=1
  PROVIDES:=kmod-qca-nss-ecm
  $(call AddDepends/qca-nss-ecm/Default)
endef

define KernelPackage/qca-nss-ecm/Description/Default
This package contains the QCA NSS Enhanced Connection Manager
endef

define AddDepends/qca-nss-ecm/Default
  SUBMENU:=Network Support
  DEPENDS:= \
	+@NSS_DRV_IPV6_ENABLE \
	+@NSS_DRV_PPE_ENABLE \
	+@NSS_DRV_TUN6RD_ENABLE \
	+@NSS_DRV_PPPOE_ENABLE \
	+@NSS_DRV_PPTP_ENABLE \
	+@NSS_DRV_VIRT_IF_ENABLE \
	+@NSS_DRV_WIFI_ENABLE \
	+kmod-qca-nss-drv \
	+kmod-nf-conntrack \
	+kmod-ppp +kmod-pppoe +kmod-pptp
endef

define KernelPackage/qca-nss-ecm/Default/install
	$(INSTALL_DIR) $(1)/etc/firewall.d $(1)/etc/init.d $(1)/usr/bin $(1)/lib/netifd/offload $(1)/etc/config $(1)/etc/uci-defaults $(1)/etc/sysctl.d
	$(INSTALL_DATA) ./files/qca-nss-ecm.firewall $(1)/etc/firewall.d/qca-nss-ecm
	$(INSTALL_BIN) ./files/qca-nss-ecm.init $(1)/etc/init.d/qca-nss-ecm
	$(INSTALL_BIN) ./files/ecm_dump.sh $(1)/usr/bin/
	$(INSTALL_BIN) ./files/on-demand-down $(1)/lib/netifd/offload/on-demand-down
	$(INSTALL_DATA) ./files/qca-nss-ecm.uci $(1)/etc/config/ecm
	$(INSTALL_DATA) ./files/qca-nss-ecm.defaults $(1)/etc/uci-defaults/99-qca-nss-ecm
	$(INSTALL_BIN) ./files/qca-nss-ecm.sysctl $(1)/etc/sysctl.d/99-qca-nss-ecm.conf
ifeq ($(CONFIG_KERNEL_IPQ_MEM_PROFILE),256)
	echo 'net.netfilter.nf_conntrack_max=2048' >> $(1)/etc/sysctl.d/99-qca-nss-ecm.conf
endif
ifeq ($(CONFIG_KERNEL_IPQ_MEM_PROFILE),512)
	echo 'net.netfilter.nf_conntrack_max=8192' >> $(1)/etc/sysctl.d/99-qca-nss-ecm.conf
endif
endef

define KernelPackage/qca-nss-ecm-standard
$(call KernelPackage/qca-nss-ecm/Default)
  DEPENDS+= \
	+PACKAGE_kmod-qca-mcs:kmod-qca-mcs \
	+PACKAGE_kmod-pppol2tp:kmod-pppol2tp \
	+PACKAGE_kmod-qca-nat46:kmod-qca-nat46
  VARIANT:=standard
endef

define KernelPackage/qca-nss-ecm-standard/description
  $(call KernelPackage/qca-nss-ecm/Description/Default)
endef

define KernelPackage/qca-nss-ecm-standard/install
$(call KernelPackage/qca-nss-ecm/Default/install, $(1))
endef

# Variant with additional features enabled for premium profile
define KernelPackage/qca-nss-ecm-premium/Default
$(call KernelPackage/qca-nss-ecm/Default)
  TITLE+:= (with premium features)
  VARIANT:=premium
  DEPENDS+:=+kmod-qca-hyfi-bridge +kmod-qca-mcs +kmod-qca-nat46
ifeq ($(CONFIG_TARGET_ipq_ipq40xx)$(CONFIG_TARGET_ipq40xx),)
  DEPENDS+=+kmod-bonding
endif
endef

define KernelPackage/qca-nss-ecm-premium/Description/Default
$(call KernelPackage/qca-nss-ecm/Description/Default)
with the premium features enabled
endef

define KernelPackage/qca-nss-ecm-premium/Default/install
$(call KernelPackage/qca-nss-ecm/install)
endef

define KernelPackage/qca-nss-ecm-premium
$(call KernelPackage/qca-nss-ecm-premium/Default)
endef

define KernelPackage/qca-nss-ecm-premium/description
$(call KernelPackage/qca-nss-ecm-premium/Description/Default)
endef

define KernelPackage/qca-nss-ecm-premium/install
$(call KernelPackage/qca-nss-ecm-standard/install, $(1))
endef

# Variant with additional features enabled for noload profile
define KernelPackage/qca-nss-ecm-noload
  $(call KernelPackage/qca-nss-ecm/Default)
  TITLE+:= (with noload features)
  PROVIDES:=kmod-qca-nss-ecm
  VARIANT:=noload
ifeq ($(CONFIG_TARGET_ipq_ipq40xx)$(CONFIG_TARGET_ipq40xx),)
  DEPENDS+=+kmod-bonding
endif
endef

define KernelPackage/qca-nss-ecm-noload/description
  $(call KernelPackage/qca-nss-ecm/Description/Default)
  When selected, this package installs the driver but does not load it at init.
endef

define KernelPackage/qca-nss-ecm-noload/install
$(call KernelPackage/qca-nss-ecm/Default/install, $(1))
	#
	# Remove the START line from the init script, so that the symlink
	# in the /etc/rc.d directory is not created.
	#
	sed -i '/START=/d' $(1)/etc/init.d/qca-nss-ecm
endef

define KernelPackage/qca-nss-ecm-premium-noload
  $(call KernelPackage/qca-nss-ecm-premium/Default)
  TITLE+:= (noload)
  PROVIDES:=kmod-qca-nss-ecm-premium
  VARIANT:=premium-noload
endef

define KernelPackage/qca-nss-ecm-premium-noload/description
  $(call KernelPackage/qca-nss-ecm-premium/Description/Default)
  When selected, this package installs the driver but does not load it at init.
endef

define KernelPackage/qca-nss-ecm-premium-noload/install
$(call KernelPackage/qca-nss-ecm-premium/Default/install, $(1))
endef

define Build/InstallDev/qca-nss-ecm
	$(INSTALL_DIR) $(1)/usr/include/qca-nss-ecm
	$(CP) $(PKG_BUILD_DIR)/exports/* $(1)/usr/include/qca-nss-ecm/
endef

define Build/InstallDev
	$(call Build/InstallDev/qca-nss-ecm,$(1))
endef

EXTRA_CFLAGS+= \
	-I$(STAGING_DIR)/usr/include/hyfibr \
	-I$(STAGING_DIR)/usr/include/qca-mcs \
	-I$(STAGING_DIR)/usr/include/qca-nss-drv \
	-I$(STAGING_DIR)/usr/include/shortcut-fe \
	-I$(STAGING_DIR)/usr/include/nat46

ECM_MAKE_OPTS:=ECM_CLASSIFIER_HYFI_ENABLE=n
ifeq ($(LOCAL_VARIANT),standard)
ECM_MAKE_OPTS+=ECM_NON_PORTED_SUPPORT_ENABLE=y \
		ECM_STATE_OUTPUT_ENABLE=y \
		ECM_INTERFACE_VLAN_ENABLE=y \
		ECM_CLASSIFIER_DSCP_ENABLE=y \
		ECM_CLASSIFIER_MARK_ENABLE=y \
		ECM_CLASSIFIER_NL_ENABLE=y \
		ECM_TRACKER_DPI_SUPPORT_ENABLE=y \
		ECM_DB_ADVANCED_STATS_ENABLE=y \
		ECM_CLASSIFIER_EMESH_ENABLE=n

ifeq ($(CONFIG_TARGET_ipq_ipq40xx)$(CONFIG_TARGET_ipq40xx),)
ECM_MAKE_OPTS+=ECM_INTERFACE_BOND_ENABLE=n
endif
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nat46),)
ECM_MAKE_OPTS+=ECM_INTERFACE_MAP_T_ENABLE=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-ovpn-link),)
ECM_MAKE_OPTS+=ECM_INTERFACE_OVPN_ENABLE=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-vxlanmgr),)
ECM_MAKE_OPTS+=ECM_INTERFACE_VXLAN_ENABLE=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-ovsmgr),)
ECM_MAKE_OPTS+=ECM_INTERFACE_OVS_BRIDGE_ENABLE=y \
		ECM_CLASSIFIER_OVS_ENABLE=y
EXTRA_CFLAGS+= -I$(STAGING_DIR)/usr/include/qca-ovsmgr
endif

ifneq ($(CONFIG_PACKAGE_kmod-macvlan),)
ECM_MAKE_OPTS+=ECM_INTERFACE_MACVLAN_ENABLE=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-mcs),)
ECM_MAKE_OPTS+=ECM_MULTICAST_ENABLE=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-ipsec),)
ECM_MAKE_OPTS+=ECM_INTERFACE_IPSEC_ENABLE=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-pppoe),)
ECM_MAKE_OPTS+= ECM_INTERFACE_PPPOE_ENABLE=y \
		ECM_INTERFACE_PPTP_ENABLE=y \
		ECM_INTERFACE_PPP_ENABLE=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-pppol2tp),)
ECM_MAKE_OPTS+=ECM_INTERFACE_L2TPV2_ENABLE=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-gre)$(CONFIG_PACKAGE_kmod-gre6),)
ECM_MAKE_OPTS+=ECM_INTERFACE_GRE_TAP_ENABLE=y \
		ECM_INTERFACE_GRE_TUN_ENABLE=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-sit),)
ECM_MAKE_OPTS+=ECM_INTERFACE_SIT_ENABLE=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-ip6-tunnel),)
ECM_MAKE_OPTS+=ECM_INTERFACE_TUNIPIP6_ENABLE=y
endif

ifneq ($(CONFIG_PACKAGE_kmod-qca-nss-drv-mscs),)
ECM_MAKE_OPTS+=ECM_CLASSIFIER_MSCS_ENABLE=y
endif

# Disable ECM IPv6 support when global IPv6 support is disabled.
ifneq ($(CONFIG_IPV6),)
ECM_MAKE_OPTS+=ECM_IPV6_ENABLE=y
endif

# Enable NSS frontend for all the platforms except ipq40xx
ifeq ($(CONFIG_TARGET_ipq_ipq40xx)$(CONFIG_TARGET_ipq40xx),)
ifneq ($(BUILD_VARIANT), nonss)
ECM_MAKE_OPTS+=ECM_FRONT_END_NSS_ENABLE=y
endif
endif

# Keeping default as ipq806x for branches that does not have subtarget framework
ifeq ($(CONFIG_TARGET_ipq),y)
subtarget:=$(SUBTARGET)
else
subtarget:=$(CONFIG_TARGET_BOARD)
endif

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/qca-nss-ecm
	$(CP) $(PKG_BUILD_DIR)/exports/* $(1)/usr/include/qca-nss-ecm
endef

define Build/Compile
	+$(MAKE) $(PKG_JOBS) -C "$(LINUX_DIR)" $(strip $(ECM_MAKE_OPTS)) \
		$(KERNEL_MAKE_FLAGS) \
		$(PKG_MAKE_FLAGS) \
		M="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" SoC="$(subtarget)" \
		EXAMPLES_BUILD_PCC="$(CONFIG_QCA_NSS_ECM_EXAMPLES_PCC)" \
		EXAMPLES_BUILD_MARK="$(CONFIG_QCA_NSS_ECM_EXAMPLES_MARK)" \
		EXAMPLES_BUILD_OVS="$(CONFIG_QCA_NSS_ECM_OVS)" \
		ECM_FRONT_END_SFE_ENABLE="$(CONFIG_QCA_ECM_SFE_SUPPORT)" \
		modules
endef

define KernelPackage/qca-nss-ecm-standard/config
menu "ECM Configuration"

	config QCA_NSS_ECM_EXAMPLES_PCC
		bool "Build PCC usage example"
		help
			Selecting this will build the PCC classifier usage example module.
		default n

	config QCA_NSS_ECM_EXAMPLES_MARK
		bool "Build Mark classifier usage example"
		help
			Selecting this will build the Mark classifier usage example module.
		default n

	config QCA_NSS_ECM_OVS
		bool "Build OVS classifier external module"
		help
			Selecting this will build the OVS classifier external module.
		default n

	config QCA_ECM_SFE_SUPPORT
		bool "Add SFE support to ECM driver"
		default n
endmenu
endef

$(eval $(call KernelPackage,qca-nss-ecm-noload))
$(eval $(call KernelPackage,qca-nss-ecm-standard))
$(eval $(call KernelPackage,qca-nss-ecm-premium-noload))
$(eval $(call KernelPackage,qca-nss-ecm-premium))
