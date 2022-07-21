include $(TOPDIR)/rules.mk

PKG_NAME:=qca-nss-dp
PKG_RELEASE:=$(AUTORELEASE)

PKG_SOURCE_URL:=https://git.codelinaro.org/clo/qsdk/oss/lklm/nss-dp.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_DATE:=2022-07-06
PKG_SOURCE_VERSION:=2976b05cb8ddfaa695fc00372c8538a3dfb32277
PKG_MIRROR_HASH:=c11d73e27385212fce6701b02146ee615d44c8e340c73917cbe4067502bdfc24

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

define KernelPackage/qca-nss-dp
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  DEPENDS:=@(TARGET_ipq807x||TARGET_ipq60xx) +kmod-qca-ssdk
  TITLE:=Kernel driver for NSS data plane
  FILES:=$(PKG_BUILD_DIR)/qca-nss-dp.ko
  AUTOLOAD:=$(call AutoLoad,31,qca-nss-dp,1)
endef

define KernelPackage/qca-nss-dp/Description
This package contains a NSS data plane driver for QCA chipset
endef

define Build/InstallDev
	mkdir -p $(1)/usr/include/qca-nss-dp
	$(CP) $(PKG_BUILD_DIR)/exports/* $(1)/usr/include/qca-nss-dp/
endef

EXTRA_CFLAGS+= \
	-I$(STAGING_DIR)/usr/include/qca-ssdk

NSS_DP_HAL_DIR:=$(PKG_BUILD_DIR)/hal
define Build/Configure
	$(LN) $(NSS_DP_HAL_DIR)/soc_ops/$(CONFIG_TARGET_BOARD)/nss_$(CONFIG_TARGET_BOARD).h \
		$(PKG_BUILD_DIR)/exports/nss_dp_arch.h
endef

define Build/Compile
	+$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		M="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" SoC="$(CONFIG_TARGET_BOARD)" \
		$(KERNEL_MAKE_FLAGS) \
		$(PKG_JOBS) \
		modules
endef

$(eval $(call KernelPackage,qca-nss-dp))
