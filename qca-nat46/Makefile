include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-nat46

PKG_MIRROR_HASH:=2ff2080bf5ac003e36b1f0df4d444413e36496c4659bd7a46ae5e2b07b9634e7
PKG_SOURCE_URL:=https://github.com/ayourtch/nat46.git
PKG_SOURCE_DATE:=2020-06-26
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=1182f30785e4274913f01a8c3d7e1b5437ae3819

PKG_MAINTAINER:=Hans Dedecker <dedeckeh@gmail.com>
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define KernelPackage/qca-nat46
  DEPENDS:=@IPV6 +kmod-nf-conntrack6
  TITLE:=Stateless NAT46 translation kernel module
  SECTION:=kernel
  SUBMENU:=Network Support
  PROVIDES:=nat46
  CONFLICTS:=nat46
  FILES:=$(PKG_BUILD_DIR)/nat46/modules/nat46.ko
  AUTOLOAD:=$(call AutoLoad,33,nat46)
endef

include $(INCLUDE_DIR)/kernel-defaults.mk

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)/nat46/modules" \
		MODFLAGS="-DMODULE -mlong-calls" \
		EXTRA_CFLAGS="-DNAT46_VERSION=\\\"$(PKG_SOURCE_VERSION)\\\"" \
		modules
		cp $(PKG_BUILD_DIR)/nat46/modules/Module.symvers $(PKG_BUILD_DIR)/Module.symvers
endef

define Build/InstallDev
	mkdir -p -m 0777 $(STAGING_DIR)/usr/include/nat46
	$(CP) $(PKG_BUILD_DIR)/nat46/modules/*.h  $(STAGING_DIR)/usr/include/nat46/
endef

$(eval $(call KernelPackage,qca-nat46))
