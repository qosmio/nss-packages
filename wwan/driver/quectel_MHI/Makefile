include $(TOPDIR)/rules.mk

PKG_NAME:=pcie_mhi
PKG_VERSION:=1.3.8
PKG_RELEASE:=1

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=gc-sections lto

define KernelPackage/pcie_mhi
  SUBMENU:=Network Devices
  TITLE:=Kernel PCIe driver for MHI device
  DEPENDS:=@(TARGET_qualcommax_ipq807x||TARGET_qualcommax_ipq50xx) \
	    +pciids +pciutils +quectel-cm
  FILES:=$(PKG_BUILD_DIR)/pcie_mhi.ko
  AUTOLOAD:=$(call AutoLoad,90,pcie_mhi)
endef

define KernelPackage/pcie_mhi/description
  Kernel module for register a custom pciemhi platform device.
endef

EXTRA_CFLAGS+= \
	-I$(STAGING_DIR)/usr/include/qca-nss-drv \
	-Wno-unused-function \
	-Wno-missing-prototypes \
	-Wno-missing-declarations

define Build/Compile
	+$(KERNEL_MAKE) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" M="$(PKG_BUILD_DIR)" \
		modules
endef

$(eval $(call KernelPackage,pcie_mhi))
