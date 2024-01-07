include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=nss-udp-st
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/nss-udp-st
  SECTION:=utils
  CATEGORY:=Utilities
  URL:=http://www.qualcomm.com
  TITLE:=NSS UDP SpeedTest
  DEPENDS:=@TARGET_qualcommax +kmod-nss-udp-st-drv
endef

define Package/nss-udp-st/description/Default
	A userspace utility for host data path nss udp speedtest
endef

TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/nss-udp-st-drv/

define Build/Compile
$(MAKE) -C $(PKG_BUILD_DIR) \
	CC="$(TARGET_CC)" \
	CFLAGS="$(TARGET_CFLAGS)" \
	LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/nss-udp-st/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nss-udp-st $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,nss-udp-st))
