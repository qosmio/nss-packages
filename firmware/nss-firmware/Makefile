#
# Copyright (C) 2022 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nss-firmware
PKG_SOURCE_DATE:=2024-07-22
PKG_SOURCE_VERSION:=8dceff47ef0ac967d01bf0dacd84d44842774af2
PKG_MIRROR_HASH:=3334a63d0b2c7afe4f6d4e3c2ac86bc3e2a0d97df17f478eeec7d29936062edf
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/qosmio/qca-sdk-nss-fw.git

PKG_LICENSE_FILES:=LICENSE.md

PKG_MAINTAINER:=Sean K <datapronix@protonmail.com>

PKG_CONFIG_DEPENDS:= \
	CONFIG_NSS_FIRMWARE_VERSION_11_4 \
	CONFIG_NSS_FIRMWARE_VERSION_12_5

include $(INCLUDE_DIR)/package.mk

RSTRIP:=:
STRIP:=:

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
	DEPENDS+= @TARGET_qualcommax_ipq807x +nss-firmware-default
	NSS_SOC:=HK
endef

define Package/nss-firmware-ipq6018
$(Package/nss-firmware-default)
	IPQ_PLATFORM=IPQ6018
	DEPENDS+= @TARGET_qualcommax_ipq60xx +nss-firmware-default
	NSS_SOC:=CP
endef

define Package/nss-firmware-ipq5018
$(Package/nss-firmware-default)
	IPQ_PLATFORM=IPQ5018
	DEPENDS+= @TARGET_qualcommax_ipq50xx +nss-firmware-default
	NSS_SOC:=MP
endef


define Package/nss-firmware-default/config
  menu "NSS Firmware Version"

  comment "Select NSS firmware version"

  choice
    prompt "Version"
    default NSS_FIRMWARE_VERSION_12_5

    config NSS_FIRMWARE_VERSION_12_5
          bool "NSS Firmware 12.5 Release 210"
          help
               This version does not work with NSS MESH

    config NSS_FIRMWARE_VERSION_11_4
          bool "NSS Firmware 11.4.0.5 Release 5"
          help
               This version works with NSS MESH
  endchoice
  endmenu
endef

ifneq ($(CONFIG_NSS_FIRMWARE_VERSION_11_4),)
   NSS_MAJOR:=11.4
   NSS_MINOR:=11.4.0.5
   NSS_REL:=5
   VERSION_PATH=$(PKG_BUILD_DIR)/QCA_Networking_2021.SPF_$(NSS_MAJOR)/CS
else
   NSS_MAJOR:=12.5
   NSS_MINOR:=12.5
   NSS_REL:=210
   VERSION_PATH=$(PKG_BUILD_DIR)/QCA_Networking_2024.SPF_$(NSS_MAJOR)/ED1
endif

define Build/Compile
endef

define Package/nss-firmware/install
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/$(IPQ_PLATFORM)
	$(TAR) --strip-components=1 -C $(PKG_BUILD_DIR)/$(IPQ_PLATFORM) -xf \
		$(VERSION_PATH)/$(IPQ_PLATFORM).ATH.$(NSS_MAJOR)/BIN-NSS*.$(NSS_MINOR)-$(NSS_REL)*$(NSS_PROFILE).tar.bz2
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
	$(call Package/nss-firmware/install,$(1))
endef

define Package/nss-firmware-ipq6018/install
	$(call Package/nss-firmware/install,$(1))
endef

define Package/nss-firmware-ipq5018/install
	$(call Package/nss-firmware/install,$(1))
endef

define Package/nss-firmware-default/install
	true
endef

$(eval $(call BuildPackage,nss-firmware-ipq8074))
$(eval $(call BuildPackage,nss-firmware-ipq6018))
$(eval $(call BuildPackage,nss-firmware-ipq5018))
$(eval $(call BuildPackage,nss-firmware-default))
