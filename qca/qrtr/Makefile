include $(TOPDIR)/rules.mk

PKG_NAME:=qrtr
PKG_RELEASE:=$(AUTORELEASE)

PKG_SOURCE_URL:=https://git.codelinaro.org/clo/qsdk/qrtr.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_DATE:=2019-07-25
PKG_SOURCE_VERSION:=cd6bedd5d00f211e6c1e3803ff2f9f53c246435e
PKG_MIRROR_HASH:=a06d2b4b11101655606b5592199c137466595e9f420c0d6780128dcb5df5f253

include $(INCLUDE_DIR)/package.mk

define Package/qrtr
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=QRTR tools
  DEPENDS:=@(TARGET_ipq807x)
endef

define Package/qrtr/description
	Set of QRTR related configuration and debugging tools.
endef

define Package/qrtr/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/qrtr-cfg $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/qrtr-lookup $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/qrtr-ns $(1)/usr/sbin
endef

$(eval $(call BuildPackage,qrtr))
