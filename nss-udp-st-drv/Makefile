include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=nss-udp-st-drv
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/$(PKG_NAME)
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Support
  DEPENDS:=@(TARGET_qualcommax||TARGET_ipq60xx) +kmod-pppoe
  TITLE:=Kernel driver for NSS UDP Speedtest
  FILES:=$(PKG_BUILD_DIR)/nss-udp-st.ko
endef

define KernelPackage/$(PKG_NAME)/Description
Kernel driver for host data path NSS UDP speedtest
endef

define KernelPackage/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
endef

ifeq ($(CONFIG_TARGET_SUBTARGET), "ipq807x")
    SOC="ipq807x_64"
	subtarget:=$(CONFIG_TARGET_SUBTARGET)
else ifeq ($(CONFIG_TARGET_BOARD), "ipq60xx")
    SOC="ipq60xx_64"
	subtarget:=$(SUBTARGET)
endif

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR)/usr/include/nss-udp-st-drv
	$(CP) $(PKG_BUILD_DIR)/exports/* $(STAGING_DIR)/usr/include/nss-udp-st-drv/
endef

EXTRA_CFLAGS+= -I$(STAGING_DIR)/usr/include/nss-udp-st-drv/

define Build/Compile
	+$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		M="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		SoC=$(SOC) \
		$(KERNEL_MAKE_FLAGS) \
		$(PKG_JOBS) \
		modules
endef

$(eval $(call KernelPackage,$(PKG_NAME)))
