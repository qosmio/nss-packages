include $(TOPDIR)/rules.mk

PKG_NAME:=qmi_wwan_q
PKG_VERSION:=1.2.9
PKG_RELEASE:=1

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

PKG_BUILD_PARALLEL:=1

define KernelPackage/qmi_wwan_q
  SUBMENU:=WWAN Support
  TITLE:=Quectel Linux USB QMI WWAN Driver
  DEPENDS:=@(TARGET_qualcommax_ipq807x||TARGET_qualcommax_ipq50xx) \
	    +kmod-usb-net \
	    +kmod-usb-wdm \
	    +kmod-qca-nss-drv \
	    +@NSS_DRV_RMNET_ENABLE \
	    +@NSS_DRV_C2C_ENABLE
  FILES:=$(PKG_BUILD_DIR)/qmi_wwan_q.ko \
	    $(PKG_BUILD_DIR)/rmnet_nss.ko
  AUTOLOAD:=$(call AutoLoad,42,rmnet_nss) \
	    $(call AutoLoad,81,qmi_wwan_q)
endef

EXTRA_CFLAGS+= \
	-I$(STAGING_DIR)/usr/include/qca-nss-drv

define Build/Compile
	+$(KERNEL_MAKE) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" M="$(PKG_BUILD_DIR)" \
		modules
endef

$(eval $(call KernelPackage,qmi_wwan_q))
