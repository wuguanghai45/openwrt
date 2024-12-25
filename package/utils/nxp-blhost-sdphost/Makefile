# SPDX-License-Identifier: GPL-2.0-or-later
include $(TOPDIR)/rules.mk

PKG_NAME:=nxp-blhost-sdphost
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/nxp-blhost-sdphost
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=NXP blhost and sdphost tools
  DEPENDS:=+libc +libstdcpp
endef

define Package/nxp-blhost-sdphost/description
  A toolset including blhost and sdphost for NXP bootloader host communication.
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	@echo "Prepared source in $(PKG_BUILD_DIR)"
endef


define Build/Compile
   $(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CXX="$(TARGET_CXX)" 
endef

define Package/nxp-blhost-sdphost/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/blhost $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sdphost $(1)/usr/bin/
endef

$(eval $(call BuildPackage,nxp-blhost-sdphost))
