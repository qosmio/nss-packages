#
# Copyright (C) 2022 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nss-firmware
PKG_SOURCE_DATE:=2022-07-12
PKG_SOURCE_VERSION:=ade6bff594377c9d9c79b45e39bf104303d919bc
PKG_MIRROR_HASH:=af0521893064b7bc52baab263e12c7db5462461ddac30d02647ed76d999b59fb
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/quic/qca-sdk-nss-fw.git

PKG_LICENSE_FILES:=LICENSE.md

PKG_MAINTAINER:=Robert Marko <robimarko@gmail.com>

include $(INCLUDE_DIR)/package.mk

RSTRIP:=:
STRIP:=:

VERSION_PATH=$(PKG_BUILD_DIR)/QCA_Networking_2022.SPF_12.0.0/ED1

NSS_VER:=12.1
NSS_REL:=022
NSS_PROFILE:=R

define Package/nss-firmware-default
	TITLE:=NSS firmware
	SECTION:=firmware
	CATEGORY:=Firmware
	URL:=$(PKG_SOURCE_URL)
	DEPENDS:=@TARGET_qualcommax
endef

define Package/nss-firmware-ipq8074
$(Package/nss-firmware-default)
	IPQ_PLATFORM=IPQ8074
	DEPENDS+= @TARGET_qualcommax_ipq807x
	NSS_SOC:=HK
endef

define Package/nss-firmware-ipq6018
$(Package/nss-firmware-default)
	IPQ_PLATFORM=IPQ6018
	DEPENDS+= @TARGET_qualcommax_ipq60xx
	NSS_SOC:=CP
endef

define Package/nss-firmware-ipq5018
$(Package/nss-firmware-default)
	IPQ_PLATFORM=IPQ5018
	DEPENDS+= @TARGET_qualcommax_ipq50xx
	NSS_SOC:=MP
endef

define Build/Compile
endef

define Package/nss-firmware/install
	$(eval NSS_ARCHIVE := $(VERSION_PATH)/$(IPQ_PLATFORM).ATH.12.0.0/BIN-NSS.FW.$(NSS_VER)-$(NSS_REL)-$(NSS_SOC).$(NSS_PROFILE).tar.bz2)
	mkdir -p $(PKG_BUILD_DIR)/$(IPQ_PLATFORM)
	$(TAR) -C $(PKG_BUILD_DIR)/$(IPQ_PLATFORM) -xf $(NSS_ARCHIVE) --strip-components=1
	$(INSTALL_DIR) $(1)/lib/firmware/
	$(INSTALL_DATA) \
		$(PKG_BUILD_DIR)/$(IPQ_PLATFORM)/retail_router0.bin \
		$(1)/lib/firmware/qca-nss0-retail.bin
ifeq ($(NSS_SOC),HK)
	$(INSTALL_DATA) \
		$(PKG_BUILD_DIR)/$(IPQ_PLATFORM)/retail_router1.bin \
		$(1)/lib/firmware/qca-nss1-retail.bin
endif
endef

define Package/nss-firmware-ipq8074/install
	$(call Package/nss-firmware/install,$1)
endef

define Package/nss-firmware-ipq6018/install
	$(call Package/nss-firmware/install,$1)
endef

define Package/nss-firmware-ipq5018/install
	$(call Package/nss-firmware/install,$1)
endef

$(eval $(call BuildPackage,nss-firmware-ipq8074))
$(eval $(call BuildPackage,nss-firmware-ipq6018))
$(eval $(call BuildPackage,nss-firmware-ipq5018))
