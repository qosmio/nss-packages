include $(TOPDIR)/rules.mk

PKG_NAME:=mhz
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL=https://github.com/wtarreau/mhz.git
PKG_SOURCE_DATE:=2022-08-17
PKG_SOURCE_VERSION:=6ec38cbb1371d20078a7a5059dd9faa5b281b2d9
PKG_MIRROR_HASH:=a98bd9f97b470606ab71c7244eb92a0955e3976986590dc9139770ffc8c9ba67

PKG_MAINTAINER:=Robert Marko <robimarko@gmail.com>

include $(INCLUDE_DIR)/package.mk

define Package/mhz
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=CPU frequency measurement utility
endef

define Package/mhz/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mhz $(1)/usr/sbin/mhz
endef

$(eval $(call BuildPackage,mhz))
